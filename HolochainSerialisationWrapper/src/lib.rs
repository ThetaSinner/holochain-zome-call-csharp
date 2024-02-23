use std::ffi::{c_char, CStr};

use holo_hash::{AgentPubKey, DnaHash};
use holochain_zome_types::{CapSecret, CellId, ExternIO, Nonce256Bits,
    Timestamp, CAP_SECRET_BYTES,
};

#[repr(C)]
pub struct ZomeCallUnsigned {
    provenance: *mut u8,
    cell_id_dna_hash: *mut u8,
    cell_id_agent_pub_key: *mut u8,
    zome_name: *mut c_char,
    fn_name: *mut c_char,
    cap_secret: *mut u8,
    payload: *mut u8,
    payload_length: u32,
    nonce: *mut u8,
    expires_at: i64,
}

#[no_mangle]
pub extern "cdecl" fn get_data_to_sign(data: *mut u8, zome_call_unsigned: ZomeCallUnsigned) {
    let zome_call_unsigned: holochain_zome_types::ZomeCallUnsigned = zome_call_unsigned.try_into().unwrap();
    let data_to_sign = zome_call_unsigned
        .data_to_sign()
        .map_err(|e| format!("Failed to get data to sign: {:?}", e)).unwrap();

    unsafe {
        // Copy the hash to the output
        for i in 0..32 {
            *data.wrapping_add(i) = data_to_sign[i];
        }
    }
}

impl TryFrom<ZomeCallUnsigned> for holochain_zome_types::ZomeCallUnsigned {
    type Error = String;

    fn try_from(zome_call_unsigned: ZomeCallUnsigned) -> Result<Self, String> {
        let provenance: holo_hash::HoloHash<holo_hash::hash_type::Agent> = unsafe {
            AgentPubKey::from_raw_39(std::slice::from_raw_parts(zome_call_unsigned.provenance, 39).to_vec())
            .map_err(|e| {
                format!("Error converting agent key for provenance: {:?}", e)
            })?
        };

        let dna_hash = unsafe {
            DnaHash::from_raw_39(std::slice::from_raw_parts(zome_call_unsigned.cell_id_dna_hash, 39).to_vec())
            .map_err(|e| format!("Error converting dna hash for cell id: {:?}", e))?
        };

        let agent_pubkey = unsafe {
            AgentPubKey::from_raw_39(std::slice::from_raw_parts(zome_call_unsigned.cell_id_agent_pub_key, 39).to_vec())
            .map_err(|e| {
                format!("Error converting agent pub key for cell id: {:?}", e)
            })?
        };

        let cap_secret: CapSecret = unsafe {
            let sized_cap_secret: [u8; CAP_SECRET_BYTES] = std::slice::from_raw_parts(zome_call_unsigned.cap_secret, CAP_SECRET_BYTES).to_vec().try_into().map_err(|e| {
                format!("Error converting cap secret: {:?}", e)
            })?;

            sized_cap_secret.into()
        };

        let nonce: Nonce256Bits = unsafe {
            let sized_nonce: [u8; 32] = std::slice::from_raw_parts(zome_call_unsigned.nonce, 32).try_into().map_err(|e| {
                format!("Error converting nonce: {:?}", e)
            })?;

            sized_nonce.into()
        };

        let payload = unsafe {
            std::slice::from_raw_parts(zome_call_unsigned.payload, zome_call_unsigned.payload_length as usize)
        };

        let raw_zome_name = unsafe {
            CStr::from_ptr(zome_call_unsigned.zome_name)
        };
        let zome_name_string = raw_zome_name.to_str().expect("Could not convert zome_name to string");

        let raw_fn_name = unsafe {
            CStr::from_ptr(zome_call_unsigned.fn_name)
        };
        let fn_name_string = raw_fn_name.to_str().expect("Could not convert fn_name to string");

        Ok(holochain_zome_types::ZomeCallUnsigned {
            provenance,
            cell_id: CellId::new(dna_hash, agent_pubkey),
            zome_name: zome_name_string.into(),
            fn_name: fn_name_string.into(),
            cap_secret: Some(cap_secret),
            payload: ExternIO(payload.to_vec()),
            nonce,
            expires_at: Timestamp(zome_call_unsigned.expires_at),
        })
    }
}
