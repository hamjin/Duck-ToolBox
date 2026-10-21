//! Qualcomm KeymasterUtils ABI observed in the supplied arm64 client. Object layout
//! and symbols vary with firmware; existence checks cannot establish ABI compatibility.
//! Calls run in a disposable subprocess so vendor output and crashes stay isolated.

use std::{ffi::c_void, mem::MaybeUninit};

use anyhow::{Context, Result};
use libloading::Library;

use crate::{
    error::DeviceRkpError,
    native_compat::{BufferMode, shared_reply_in_bounds},
    protocol::{BUFFER_SIZE, command_response_payload},
    status::LIBRARY_PATH,
};

type Constructor = unsafe extern "C" fn(*mut c_void, i32);
type Destructor = unsafe extern "C" fn(*mut c_void);
type SendCommand = unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut c_void, u32) -> i32;
type Initialize = unsafe extern "C" fn(*mut c_void, u32, *mut VendorBlob);
type SendShared = unsafe extern "C" fn(*mut c_void, *const VendorBlob, *mut VendorBlob) -> i32;

#[repr(C)]
struct VendorBlob {
    data: *mut u8,
    length: usize,
}

#[derive(Clone, Copy)]
enum TransportFunctions {
    Raw(SendCommand),
    Shared {
        initialize: Initialize,
        send: SendShared,
    },
}

// The reference client allocates 0x40 bytes for this vendor class. Keep allocation
// aligned and never inspect its fields; only its constructor/destructor may own them.
#[repr(C, align(16))]
struct VendorObject([MaybeUninit<u8>; 0x40]);

struct Session {
    object: Box<VendorObject>,
    destructor: Destructor,
    transport: TransportFunctions,
    _library: Library,
}

impl Session {
    fn open(buffer: BufferMode) -> Result<Self> {
        // SAFETY: only this adapter resolves the fixed vendor ABI. It is called only
        // on Android arm64 and in an isolated worker; unsupported firmware may fail.
        let library: Library = unsafe {
            libloading::os::unix::Library::open(
                Some(LIBRARY_PATH),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        }
        .context("load KeymasterUtils")?
        .into();
        let constructor = *unsafe {
            library.get::<Constructor>(
                b"_ZN14keymasterutils14KeymasterUtilsC1E26keymaster_security_level_t\0",
            )
        }
        .context("resolve KeymasterUtils constructor")?;
        let destructor =
            *unsafe { library.get::<Destructor>(b"_ZN14keymasterutils14KeymasterUtilsD1Ev\0") }
                .context("resolve KeymasterUtils destructor")?;
        // Resolve only the selected ABI, so a missing alternative cannot disable
        // the other transport. Each attempt has its own process and Session.
        let transport = match buffer {
            BufferMode::Raw => TransportFunctions::Raw(
                *unsafe {
                    library.get::<SendCommand>(
                        b"_ZN14keymasterutils14KeymasterUtils8send_cmdEPvjS1_j\0",
                    )
                }
                .context("resolve KeymasterUtils send_cmd")?,
            ),
            BufferMode::Shared => TransportFunctions::Shared {
                initialize: *unsafe {
                    library.get::<Initialize>(
                        b"_ZN14keymasterutils14KeymasterUtils4initEjP16keymaster_blob_t\0",
                    )
                }
                .context("resolve KeymasterUtils init")?,
                send: *unsafe {
                    library.get::<SendShared>(
                        b"_ZN14keymasterutils14KeymasterUtils7sendCmdERK16keymaster_blob_tPS1_\0",
                    )
                }
                .context("resolve KeymasterUtils sendCmd")?,
            },
        };
        let mut object = Box::new(VendorObject([MaybeUninit::new(0); 0x40]));
        // SAFETY: aligned writable storage stays at a stable address until Drop.
        // security_level 1 is TRUSTED_ENVIRONMENT in the observed vendor interface.
        unsafe { constructor(object.as_mut() as *mut VendorObject as *mut c_void, 1) };
        Ok(Self {
            object,
            destructor,
            transport,
            _library: library,
        })
    }

    fn request(&mut self, request: &[u8]) -> Result<Vec<u8>> {
        let command = u32::from_le_bytes(
            request
                .get(..4)
                .context("missing native command")?
                .try_into()?,
        );
        match self.transport {
            TransportFunctions::Raw(send) => self.raw_request(command, request, send),
            TransportFunctions::Shared { initialize, send } => {
                self.shared_request(command, request, initialize, send)
            }
        }
    }

    fn raw_request(&mut self, command: u32, request: &[u8], send: SendCommand) -> Result<Vec<u8>> {
        let mut request = request.to_vec();
        // A nonzero status sentinel prevents untouched response storage looking valid.
        let mut response = vec![0; BUFFER_SIZE];
        response[..4].copy_from_slice(&i32::MIN.to_le_bytes());
        // SAFETY: live class instance and disjoint writable buffers remain valid for
        // the synchronous call. Both sizes fit u32 and match their allocations.
        let status = unsafe {
            (send)(
                self.object.as_mut() as *mut VendorObject as *mut c_void,
                request.as_mut_ptr().cast(),
                request.len() as u32,
                response.as_mut_ptr().cast(),
                response.len() as u32,
            )
        };
        if status != 0 {
            return Err(DeviceRkpError::Transport(format!("send_cmd returned {status}")).into());
        }
        command_response_payload(command, &response)
    }

    fn shared_request(
        &mut self,
        command: u32,
        request: &[u8],
        initialize: Initialize,
        send: SendShared,
    ) -> Result<Vec<u8>> {
        let mut input = VendorBlob {
            data: std::ptr::null_mut(),
            length: 0,
        };
        let mut output = VendorBlob {
            data: std::ptr::null_mut(),
            length: 0,
        };
        let object = self.object.as_mut() as *mut VendorObject as *mut c_void;
        // SAFETY: the observed init ABI writes the command into its owned shared
        // buffer and returns a writable payload span which lives until Session drops.
        unsafe { initialize(object, command, &mut input) };
        let payload = &request[4..];
        let start = input.data as usize;
        let capacity = input.length;
        if input.data.is_null()
            || capacity > BUFFER_SIZE
            || payload.is_empty()
            || payload.len() > capacity
        {
            return Err(DeviceRkpError::InvalidResponse(
                "invalid vendor shared request buffer".into(),
            )
            .into());
        }
        // SAFETY: the vendor-owned span has sufficient checked capacity and is
        // disjoint from the immutable Rust request. The Session owns its lifetime.
        unsafe { std::ptr::copy_nonoverlapping(payload.as_ptr(), input.data, payload.len()) };
        input.length = payload.len();
        // SAFETY: both blob descriptors and the class instance remain live during
        // this synchronous call. sendCmd owns the shared-buffer request/reply layout.
        let status = unsafe { send(object, &input, &mut output) };
        if status != 0 {
            return command_response_payload(
                command,
                &[status.to_le_bytes(), 0u32.to_le_bytes()].concat(),
            );
        }
        if !shared_reply_in_bounds(
            start,
            capacity,
            payload.len(),
            output.data as usize,
            output.length,
        ) {
            return Err(DeviceRkpError::InvalidResponse(
                "invalid vendor shared response buffer".into(),
            )
            .into());
        }
        // SAFETY: the validated reply lies inside the still-live shared allocation,
        // beyond the request. Copy it before the vendor destructor releases storage.
        Ok(unsafe { std::slice::from_raw_parts(output.data, output.length) }.to_vec())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: destructor runs once while both the object and library are live.
        unsafe { (self.destructor)(self.object.as_mut() as *mut VendorObject as *mut c_void) };
    }
}

pub(crate) fn request(bytes: &[u8], buffer: BufferMode) -> Result<Vec<u8>> {
    Session::open(buffer)?.request(bytes)
}
