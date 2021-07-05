use std::collections::{
    HashSet,
    HashMap
};
use std::sync::{Arc};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use telnet_codec::{TelnetEvent};

const NULL: u8 = 0;
const BEL: u8 = 7;
const CR: u8 = 13;
const LF: u8 = 10;
const EOR: u8 = 239;
const NOP: u8 = 241;
const GA: u8 = 249;
const WILL: u8 = 251;
const WONT: u8 = 252;
const DO: u8 = 253;
const DONT: u8 = 254;
const SGA: u8 = 3;

// The following are MUD-relevant sub-options/protocols.
// telopt_eor is used for prompts.
const TELOPT_EOR: u8 = 25;
// NAWS - Negotiate About Window Size
const NAWS: u8 = 31;
// LINEMODE - signifies that the client will not send anything without a line terminator.
const LINEMODE: u8 = 34;

// MNES: Mud New-Environ standard
const MNES: u8 = 39;

// MUD eXtension Protocol
const MXP: u8 = 91;

// Mud Server Status Protocol
const MSSP: u8 = 70;

// Compression
// const MCCP1: u8 = 85 - this is deprecrated
// NOTE: MCCP2 and MCCP3 is currently disabled.
const MCCP2: u8 = 86;
const MCCP3: u8 = 87;

// GMCP - Generic Mud Communication Protocol
const GMCP: u8 = 201;

// MSDP - Mud Server Data Protocol
const MSDP: u8 = 69;

// TTYPE - Terminal Type
const TTYPE: u8 = 24;

#[derive(Default, Clone)]
pub struct TelnetOptionPerspective {
    pub enabled: bool,
    // Negotiating is true if WE have sent a request.
    pub negotiating: bool
}

#[derive(Default, Clone)]
pub struct TelnetOptionState {
    pub remote: TelnetOptionPerspective,
    pub local: TelnetOptionPerspective,
}

#[derive(Default, Clone)]
pub struct TelnetOption {
    pub allow_local: bool,
    pub allow_remote: bool,
    pub start_local: bool,
    pub start_remote: bool,
}

#[derive(Clone, Debug)]
pub struct TelnetConfig {
    pub client_name: String,
    pub client_version: String,
    pub encoding: String,
    pub color: u8,
    pub width: u16,
    pub height: u16,
    pub oob: bool,
    pub screen_reader: bool
}

impl Default for TelnetConfig {
    fn default() -> Self {
        TelnetConfig {
            client_name: "UNKNOWN".to_string(),
            client_version: "UNKNOWN".to_string(),
            encoding: "ascii".to_string(),
            color: 0,
            width: 78,
            height: 24,
            oob: false,
            screen_reader: false
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct TelnetHandshakes {
    pub local: HashSet<u8>,
    pub remote: HashSet<u8>,
    pub ttype: HashSet<u8>
}

impl TelnetHandshakes {
    pub fn len(&self) -> usize {
        self.local.len() + self.remote.len() + self.ttype.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct MuTelnet {
    op_state: HashMap<u8, TelnetOptionState>,
    config: TelnetConfig,
    handshakes_left: TelnetHandshakes,
    ttype_count: u8,
    ttype_last: Option<String>,
    telnet_options: Arc<HashMap<u8, TelnetOption>>,
    pub send_events: Vec<TelnetEvent>

}

impl MuTelnet {
    pub fn new(telnet_options: Arc<HashMap<u8, TelnetOption>>) -> Self {
        Self {
            op_state: Default::default(),
            config: Default::default(),
            handshakes_left: Default::default(),
            ttype_count: 0,
            ttype_last: None,
            telnet_options,
            send_events: Default::default()
        }
    }

    pub fn start(&mut self) {
        let mut start_local = HashSet::new();
        let mut start_remote = HashSet::new();

        for (op, option) in self.telnet_options.iter() {
            self.op_state.insert(*op, TelnetOptionState::default());
            if let Some(state) = self.op_state.get_mut(op) {
                if option.start_remote {
                    start_remote.insert(*op);
                    self.handshakes_left.remote.insert(*op);
                    state.remote.negotiating = true;
                }
                if option.start_local {
                    start_local.insert(*op);
                    self.handshakes_left.local.insert(*op);
                    state.local.negotiating = true;
                }

            }
        }

        for op in start_local {
            self.send_events.push(TelnetEvent::Negotiate(WILL, op));
        }

        for op in start_remote {
            self.send_events.push(TelnetEvent::Negotiate(DO, op));
        }
    }

    pub fn format_string(in_str: &str) -> String {
        let cleaned = str::replace(in_str, "\r", "");
        str::replace(&cleaned, "\n", "\r\n")
    }

    pub fn send_text(&mut self, in_str: &str) {
        let cleaned = Self::format_string(in_str);
        self.send_events.push(TelnetEvent::Data(Bytes::from(cleaned)));
    }

    pub fn send_line(&mut self, in_str: &str) {
        let mut cleaned = Self::format_string(in_str);
        if !cleaned.ends_with("\r\n") {
            cleaned.push_str("\r\n");
        }
        self.send_events.push(TelnetEvent::Data(Bytes::from(cleaned)));
    }

    pub fn send_prompt(&mut self, in_str: &str) {
        // TODO: Add proper prompt handling.
        self.send_line(in_str);
    }

    pub fn receive_negotiate(&mut self, command: u8, op: u8) -> bool {
        // This means we received an IAC will/wont/do/dont...
        // This function returns true/false depending on if its Config changed.
        let mut handshake: u8 = 0;
        let mut enable_local = false;
        let mut disable_local = false;
        let mut enable_remote = false;
        let mut disable_remote = false;
        let mut handshake_remote: u8 = 0;
        let mut handshake_local: u8 = 0;
        let mut respond: u8 = 0;

        if let Some(state) = self.op_state.get_mut(&op) {
            // We DO have a handler for this option... that means we support it!

            match command {
                WILL => {
                    // The remote host has sent a WILL. They either want to Locally-Enable op, or are
                    // doing so at our request.
                    if !state.remote.enabled {
                        if state.remote.negotiating {
                            state.remote.negotiating = false;
                        }
                        else {
                            respond = DO;
                        }
                        handshake = op;
                        handshake_remote = op;
                        enable_remote = true;
                        state.remote.enabled = true;
                    }
                },
                WONT => {
                    // The client has refused an option we wanted to enable. Alternatively, it has
                    // disabled an option that was on.
                    if state.remote.negotiating {
                        handshake = op;
                        handshake_remote = op;
                    }
                    state.remote.negotiating = false;
                    if state.remote.enabled {
                        disable_remote = true;
                        state.remote.enabled = false;
                    }
                },
                DO => {
                    // The client wants the Server to enable Option, or they are acknowledging our
                    // desire to do so.
                    if !state.local.enabled {
                        if state.local.negotiating {
                            state.local.negotiating = false;
                        }
                        else {
                            respond = WILL;
                        }
                        handshake = op;
                        handshake_local = op;
                        enable_local = true;
                        state.local.enabled = true;
                    }
                },
                DONT => {
                    // The client wants the server to disable Option, or are they are refusing our
                    // desire to do so.
                    if state.local.negotiating {
                        handshake = op;
                        handshake_local = op;
                    }
                    state.local.negotiating = false;
                    if state.local.enabled {
                        disable_local = true;
                        state.local.enabled = false
                    }
                },
                _ => {
                    // This cannot actually happen.
                }
            }
        } else {
            // We do not have a handler for this option, whatever it is... do not support.
            respond = match command {
                WILL => DONT,
                DO => WONT,
                _ => 0
            };
        }
        let mut changed: bool = false;

        if respond > 0 {
            self.send_events.push(TelnetEvent::Negotiate(respond, op));
        }
        if handshake_local > 0 {
            self.handshakes_left.local.remove(&handshake_local);
        }
        if handshake_remote > 0 {
            self.handshakes_left.remote.remove(&handshake_remote);
        }
        if enable_local {
            changed = self.enable_local(op);
        }
        if disable_local {
            changed = self.disable_local(op);
        }
        if enable_remote {
            changed = self.enable_remote(op);
        }
        if disable_remote {
            changed = self.disable_remote(op);
        }
        if handshake > 0 {
            //self.check_ready();
        }
        changed
    }

    fn enable_remote(&mut self, op: u8) -> bool {
        match op {
            //NAWS => self.config.naws = true,
            TTYPE => {
                self.request_ttype();
            },
            //LINEMODE => self.config.linemode = true,
            _ => {
                // Whatever this option is.. well, whatever.
            }
        }
        false
    }

    fn disable_remote(&mut self, op: u8) -> bool {
        match op {
            NAWS => {
                //self.config.naws = false;
                self.config.width = 78;
                self.config.height = 24;
                return true;
            }
            TTYPE => {
                //self.config.ttype = false;
                self.handshakes_left.ttype.clear();
            },
            //LINEMODE => self.config.linemode = false,
            _ => {
                // Whatever this option is.. well, whatever.
            }
        }
        false
    }

    fn enable_local(&mut self, op: u8) -> bool {
        match op {
            SGA => {
                //self.config.sga = true;
            },
            _ => {

            }
        }
        false
    }

    fn disable_local(&mut self, op: u8) -> bool {
        match op {
            SGA => {
                //self.config.sga = false;
            },
            _ => {

            }
        }
        false
    }

    pub fn handle_sub(&mut self, op: u8, mut data: Bytes) -> bool {
        // This returns whether self.config changed as a result.
        if !self.op_state.contains_key(&op) {
            // Only if we can get a handler, do we want to care about this.
            // All other sub-data is ignored.
            return false;
        }
        let mut changed = false;
        match op {
            NAWS => {
                changed = self.receive_naws(data);
            },
            TTYPE => {
                changed = self.receive_ttype(data);
            }
            _ => {}
        }
        changed
    }

    fn request_ttype(&mut self) {
        let mut data = BytesMut::with_capacity(1);
        data.put_u8(1);
        self.send_events.push(TelnetEvent::SubNegotiate(TTYPE, data.freeze()));
    }

    fn receive_ttype(&mut self, mut data: Bytes) -> bool {

        if data.len() < 2 {
            return false;
        }

        if self.handshakes_left.ttype.is_empty() {
            return false;
        }

        if data[0] != 0 {
            return false;
        }

        data.advance(1);

        if let Ok(s) = String::from_utf8(data.to_vec()) {
            let upper = s.trim().to_uppercase();

            match self.ttype_count {
                0 => {
                    self.ttype_last = Some(upper.clone());
                    self.receive_ttype_0(upper.clone());
                    self.ttype_count += 1;
                    self.handshakes_left.ttype.remove(&0);
                    self.request_ttype();
                    return true;
                },
                1 | 2 => {
                    if let Some(last) = self.ttype_last.clone() {
                        if last.eq(&upper) {
                            // This client does not support advanced ttype. Ignore further
                            // calls to TTYPE and consider this complete.
                            self.handshakes_left.ttype.clear();
                            self.ttype_last = None;
                            //self.check_ready();
                        } else {
                            match self.ttype_count {
                                1 => {
                                    self.receive_ttype_1(upper.clone());
                                    self.ttype_last = Some(upper.clone());
                                    return true;
                                },
                                2 => {
                                    self.receive_ttype_2(upper.clone());
                                    self.ttype_last = None;
                                    self.handshakes_left.ttype.clear();
                                    return true;
                                }
                                _ => {}
                            }
                            if self.handshakes_left.ttype.is_empty() {
                                //self.check_ready();
                            }
                        }
                    }
                    return false;
                }
                _ => {
                    // This shouldn't happen.
                }
            }
        }

        false
    }

    fn receive_ttype_0(&mut self, data: String) {
        // The first TTYPE receives the name of the client.
        // version might also be in here as a second word.
        if data.contains(" ") {
            let results: Vec<&str> = data.splitn(1, " ").collect();
            self.config.client_name = String::from(results[0]);
            self.config.client_version = String::from(results[1]);
        } else {
            self.config.client_name = data;
        }

        // Now that the name and version (may be UNKNOWN) are set... we can deduce capabilities.
        let mut extra_check = false;
        match self.config.client_name.as_str() {
            "ATLANTIS" | "CMUD" | "KILDCLIENT" | "MUDLET" | "MUSHCLIENT" | "PUTTY" | "BEIP" |
            "POTATO" | "TINYFUGUE" => {
                if self.config.color < 2 {
                    self.config.color = 2
                }
            }
            _ => {
                extra_check = true;
            }
        }
        if extra_check {
            if self.config.client_name.starts_with("XTERM") || self.config.client_name.ends_with("-256COLOR") {
                if self.config.color < 2 {
                    self.config.color = 2
                }
            }
        }
    }

    fn receive_ttype_1(&mut self, data: String) {
        if data.starts_with("XTERM") || data.ends_with("-256COLOR") {
            if self.config.color < 2 {
                self.config.color = 2
            }
        }
        self.handshakes_left.ttype.remove(&1);
    }

    fn receive_ttype_2(&mut self, data: String) {
        if !data.starts_with("MTTS ") {
            return;
        }
        let results: Vec<&str> = data.splitn(2, " ").collect();
        let value = String::from(results[1]);
        let mtts: usize = value.parse().unwrap_or(0);
        if mtts == 0 {
            return;
        }
        if (1 & mtts) == 1 {
            if self.config.color < 1 {
                self.config.color = 1
            }
        }
        if (2 & mtts) == 2 {
            //self.config.vt100 = true;
        }
        if (4 & mtts) == 4 {
            self.config.encoding = "utf8".to_string();
        }
        if (8 & mtts) == 8 {
            if self.config.color < 2 {
                self.config.color = 2
            }
        }
        if (16 & mtts) == 16 {
            //self.config.mouse_tracking = true;
        }
        if (32 & mtts) == 32 {
            //self.config.osc_color_palette = true;
        }
        if (64 & mtts) == 64 {
            self.config.screen_reader = true;
        }
        if (128 & mtts) == 128 {
            //self.config.proxy = true;
        }
        if (256 & mtts) == 256 {
            //self.config.truecolor = true;
        }
        if (512 & mtts) == 512 {
            //self.config.mnes = true;
        }
        self.handshakes_left.ttype.remove(&2);
    }

    fn receive_naws(&mut self, mut data: Bytes) -> bool {
        if data.len() >= 4 {
            let old_width = self.config.width;
            let old_height = self.config.height;
            self.config.width = data.get_u16();
            self.config.height = data.get_u16();
            return !((old_width == self.config.width) & (old_height == self.config.height))
        }
        false
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
