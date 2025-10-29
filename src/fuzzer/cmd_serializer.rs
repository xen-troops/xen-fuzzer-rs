enum CmdTags {
    //    Nop,
    SetHvcArgVal, // arg no, value
    SetHvcArgBuf, // arn no, buffer
    Hvc,          // perform hvc #op
    FixupBufPtr,  // fixup pointer to data buffer
}

impl From<CmdTags> for u8 {
    fn from(value: CmdTags) -> Self {
        match value {
            //	    CmdTags::Nop => 0,
            CmdTags::SetHvcArgVal => 1,
            CmdTags::SetHvcArgBuf => 2,
            CmdTags::Hvc => 3,
	    CmdTags::FixupBufPtr => 4,
        }
    }
}

pub struct CmdSerializer {
    pub data: Vec<u8>,
}

impl CmdSerializer {
    pub fn new() -> Self {
        CmdSerializer { data: vec![] }
    }

    fn emit_u64(&mut self, data: u64) {
        self.data.extend_from_slice(&data.to_le_bytes());
    }

    pub fn emit_hvc_arg(&mut self, reg_id: u8, data: u64) {
        self.data.push(CmdTags::SetHvcArgVal.into());
        self.data.push(reg_id);
        self.emit_u64(data);
    }

    pub fn emit_hvc_buf(&mut self, reg_id: u8, data: &[u8]) {
        self.data.push(CmdTags::SetHvcArgBuf.into());
        self.data.push(reg_id);
        self.emit_u64(data.len() as u64);
        self.data.extend_from_slice(data);
    }

    pub fn emit_hvc(&mut self, op: u64) {
        self.data.push(CmdTags::Hvc.into());
        self.emit_u64(op);
    }

    /// In buffer for arg <reg_id>, update buf ptr at <field_offset>
    pub fn emit_fixup_buf_ptr(&mut self, reg_id: u8, field_offset: usize) {
        self.data.push(CmdTags::FixupBufPtr.into());
        self.data.push(reg_id);
        self.emit_u64(field_offset as u64);
    }
}

#[enum_delegate::register]
pub trait CmdSerializable {
    fn emit_cmds(&self, serializer: &mut CmdSerializer);
}
