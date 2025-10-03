use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::UdpSocket;

#[derive(Debug, PartialEq, Clone, Copy)]
enum OpCode {
    QUERY = 0,
    IQUERY = 1,
    STATUS = 2,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum ResponseCode {
    NOERR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NAMERR = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl ResponseCode {
    fn from_num(num: u8) -> ResponseCode {
        match num {
            1 => ResponseCode::FORMERR,
            2 => ResponseCode::SERVFAIL,
            3 => ResponseCode::NAMERR,
            4 => ResponseCode::NOTIMP,
            5 => ResponseCode::REFUSED,
            0 | _ => ResponseCode::NOERR,
        }
    }
}

impl OpCode {
    fn from_num(num: u8) -> OpCode {
        match num {
            1 => OpCode::IQUERY,
            2 => OpCode::STATUS,
            0 | _ => OpCode::QUERY,
        }
    }
}

struct BufHandler {
    buf: [u8; 512],
    pos: usize,
}

impl BufHandler {
    fn new() -> BufHandler {
        BufHandler {
            buf: [0; 512],
            pos: 0,
        }
    }

    fn read(&mut self) -> Result<u8, String> {
        if self.pos >= 512 {
            return Err("End of buffer".to_string());
        }
        let value = self.buf[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        Ok((self.read()? as u16) << 8 | (self.read()? as u16))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        Ok((self.read_u16()? as u32) << 16 | (self.read_u16()? as u32))
    }

    fn get_pos(&self) -> usize {
        return self.pos;
    }

    fn read_qname(&mut self, out: &mut String) -> Result<(), String> {
        let mut delim = "";
        let mut jumped = false;
        let mut offset = self.pos;

        loop {
            let len = self.buf[offset];

            // end of name
            if len == 0 {
                if !jumped {
                    self.pos = offset + 1;
                }
                break;
            }

            // pointer (compression)
            if len & 0xC0 == 0xC0 {
                let b2 = self.buf[offset + 1] as u16;
                let pointer = (((len as u16) ^ 0xC0) << 8) | b2;

                if !jumped {
                    self.pos = offset + 2;
                }
                offset = pointer as usize;
                jumped = true;
            } else {
                offset += 1;
                let label = &self.buf[offset..offset + (len as usize)];
                out.push_str(delim);
                out.push_str(&String::from_utf8_lossy(label).to_lowercase());
                delim = ".";
                offset += len as usize;
            }
        }
        Ok(())
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn write(&mut self, data: u8) -> Result<(), String> {
        if self.pos >= 512 {
            return Err("End of buffer".to_string());
        }
        self.buf[self.pos] = data;
        self.pos += 1;
        Ok(())
    }

    fn write_u16(&mut self, data: u16) -> Result<(), String> {
        self.write((data >> 8) as u8)?;
        self.write(data as u8)?;
        Ok(())
    }

    fn write_u32(&mut self, data: u32) -> Result<(), String> {
        self.write_u16((data >> 16) as u16)?;
        self.write_u16(data as u16)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &String) -> Result<(), String> {
        for split in qname.split(".") {
            self.write(split.len() as u8)?;
            for byte in split.bytes() {
                self.write(byte)?;
            }
        }
        self.write(0)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct DnsHeader {
    id: u16,                     // 16 Byte
    query: bool,                 // 1 Bit
    opcode: OpCode,              // 4 Bit
    authoritative_answer: bool,  // 1 Bit
    truncation: bool,            // 1 Bit,
    recursion_desired: bool,     // 1 Bit
    recursion_available: bool,   // 1 Bit
    z: u8,                       // 3 Bit
    response_code: ResponseCode, // 4 Bit

    questions: u16,   // 16 Byte
    answers: u16,     // 16 Byte
    nameservers: u16, // 16 Byte
    additionals: u16, // 16 Byte
}

impl DnsHeader {
    fn new() -> DnsHeader {
        DnsHeader {
            id: 0,
            query: false,
            opcode: OpCode::QUERY,
            authoritative_answer: false,
            truncation: false,
            recursion_desired: false,
            recursion_available: false,
            z: 0,
            response_code: ResponseCode::NOERR,

            questions: 0,
            answers: 0,
            nameservers: 0,
            additionals: 0,
        }
    }

    fn read(&mut self, buf_handler: &mut BufHandler) -> Result<(), String> {
        self.id = buf_handler.read_u16()?;
        let flags = buf_handler.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        self.query = ((a >> 7) & 0x1) == 1;
        self.opcode = OpCode::from_num((a >> 3) & 0xF);
        self.authoritative_answer = (a >> 2 & 0x1) == 1;
        self.truncation = (a >> 1 & 0x1) == 1;
        self.recursion_desired = (a & 0x1) == 1;

        self.recursion_available = ((b >> 7) & 0x1) == 1;
        self.z = (b >> 4) & 0xF;
        self.response_code = ResponseCode::from_num(b & 0xF);

        self.questions = buf_handler.read_u16()?;
        self.answers = buf_handler.read_u16()?;
        self.nameservers = buf_handler.read_u16()?;
        self.additionals = buf_handler.read_u16()?;

        Ok(())
    }

    fn write(&self, buf_handler: &mut BufHandler) -> Result<(), String> {
        buf_handler.write_u16(self.id)?;

        buf_handler.write(
            (self.query as u8) << 7
                | (self.opcode as u8) << 3
                | (self.authoritative_answer as u8) << 2
                | (self.truncation as u8) << 1
                | (self.recursion_desired as u8),
        )?;

        buf_handler.write(
            (self.recursion_available as u8) << 7 | self.z << 4 | (self.response_code as u8),
        )?;

        buf_handler.write_u16(self.questions)?;
        buf_handler.write_u16(self.answers)?;
        buf_handler.write_u16(self.nameservers)?;
        buf_handler.write_u16(self.additionals)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum QueryType {
    A,
    NS,
    CNAME,
    MX,
    AAAA,
    UNKNOWN,
}

impl QueryType {
    fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN,
        }
    }

    fn to_num(&self) -> u16 {
        match *self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::UNKNOWN => 0,
        }
    }
}

#[derive(Debug, PartialEq)]
struct DnsQuestion {
    name: String,
    qtype: QueryType,
}

impl DnsQuestion {
    fn new() -> DnsQuestion {
        DnsQuestion {
            name: String::from(""),
            qtype: QueryType::A,
        }
    }

    fn read(&mut self, buf_handler: &mut BufHandler) -> Result<(), String> {
        buf_handler.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buf_handler.read_u16()?);
        let _qclass = buf_handler.read_u16()?;
        Ok(())
    }

    fn write(&self, buf_handler: &mut BufHandler) -> Result<(), String> {
        buf_handler.write_qname(&self.name)?;
        buf_handler.write_u16(self.qtype.to_num())?;
        buf_handler.write_u16(1)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    },
    NS {
        domain: String,
        ttl: u32,
        host: String,
    },
    CNAME {
        domain: String,
        ttl: u32,
        host: String,
    },
    MX {
        domain: String,
        ttl: u32,
        priority: u16,
        host: String,
    },
    AAAA {
        domain: String,
        ttl: u32,
        addr: Ipv6Addr,
    },
}

impl DnsRecord {
    fn read(buf_handler: &mut BufHandler) -> Result<DnsRecord, String> {
        let mut qname = String::new();
        buf_handler.read_qname(&mut qname)?;

        let qtype = QueryType::from_num(buf_handler.read_u16()?);

        let _qclass = buf_handler.read_u16()?;
        let ttl = buf_handler.read_u32()?;
        let _len = buf_handler.read_u16()?;

        match qtype {
            QueryType::A => Ok(DnsRecord::A {
                domain: qname,
                addr: Ipv4Addr::new(
                    buf_handler.read()?,
                    buf_handler.read()?,
                    buf_handler.read()?,
                    buf_handler.read()?,
                ),
                ttl: ttl,
            }),
            QueryType::NS => {
                let mut ns = String::new();
                buf_handler.read_qname(&mut ns)?;
                Ok(DnsRecord::NS {
                    domain: qname,
                    ttl: ttl,
                    host: ns,
                })
            }
            QueryType::CNAME => {
                let mut cname = String::new();
                buf_handler.read_qname(&mut cname)?;
                Ok(DnsRecord::CNAME {
                    domain: qname,
                    ttl: ttl,
                    host: cname,
                })
            }
            QueryType::MX => {
                let priority = buf_handler.read_u16()?;
                let mut mx = String::new();
                buf_handler.read_qname(&mut mx)?;

                Ok(DnsRecord::MX {
                    domain: qname,
                    ttl: ttl,
                    priority: priority,
                    host: mx,
                })
            }
            QueryType::AAAA => Ok(DnsRecord::AAAA {
                domain: qname,
                ttl: ttl,
                addr: Ipv6Addr::new(
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                    buf_handler.read_u16()?,
                ),
            }),

            _ => Ok(DnsRecord::UNKNOWN {
                domain: qname,
                qtype: qtype.to_num(),
            }),
        }
    }

    fn write(&self, buf_handler: &mut BufHandler) -> Result<(), String> {
        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::A.to_num())?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;
                buf_handler.write_u16(4)?;

                for octet in addr.octets() {
                    buf_handler.write(octet)?;
                }
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::AAAA.to_num())?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;
                buf_handler.write_u16(16)?;

                for segment in addr.segments() {
                    buf_handler.write_u16(segment)?;
                }
            }
            DnsRecord::NS {
                ref domain,
                ttl,
                ref host,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::NS.to_num())?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;

                buf_handler.write_u16((host.len() + 2) as u16)?;
                buf_handler.write_qname(host)?;
            }
            DnsRecord::CNAME {
                ref domain,
                ttl,
                ref host,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::CNAME.to_num())?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;

                buf_handler.write_u16((host.len() + 2) as u16)?;
                buf_handler.write_qname(host)?;
            }

            DnsRecord::MX {
                ref domain,
                ttl,
                ref host,
                priority,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::MX.to_num())?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;

                buf_handler.write_u16((host.len() + 4) as u16)?;
                buf_handler.write_u16(priority)?;
                buf_handler.write_qname(host)?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    nameservers: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            nameservers: Vec::new(),
            additionals: Vec::new(),
        }
    }

    fn from_buffer(buf_handler: &mut BufHandler) -> Result<Self, String> {
        let mut packet = Self::new();
        packet.read(buf_handler)?;
        Ok(packet)
    }

    fn read(&mut self, buf_reader: &mut BufHandler) -> Result<(), String> {
        self.header.read(buf_reader)?;

        for _ in 0..self.header.questions {
            let mut question = DnsQuestion::new();
            question.read(buf_reader)?;
            self.questions.push(question);
        }

        for _ in 0..self.header.answers {
            self.answers.push(DnsRecord::read(buf_reader)?);
        }

        for _ in 0..self.header.nameservers {
            self.nameservers.push(DnsRecord::read(buf_reader)?);
        }

        for _ in 0..self.header.additionals {
            self.additionals.push(DnsRecord::read(buf_reader)?);
        }

        Ok(())
    }

    fn write(&mut self, buf_handler: &mut BufHandler) -> Result<(), String> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.nameservers = self.nameservers.len() as u16;
        self.header.additionals = self.additionals.len() as u16;

        self.header.write(buf_handler)?;

        for question in self.questions.iter() {
            question.write(buf_handler)?;
        }

        for answer in self.answers.iter() {
            answer.write(buf_handler)?;
        }

        for nameserver in self.nameservers.iter() {
            nameserver.write(buf_handler)?;
        }

        for additional in self.additionals.iter() {
            additional.write(buf_handler)?;
        }

        Ok(())
    }
}

fn lookup(qname: &String, qtype: QueryType, addr: Ipv4Addr) -> Result<DnsPacket, String> {
    let udp_socket = UdpSocket::bind("0.0.0.0:34354").unwrap();
    let mut packet = DnsPacket::new();
    let mut buf_handler = BufHandler::new();

    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion {
        name: qname.to_string(),
        qtype: qtype,
    });
    packet.write(&mut buf_handler)?;

    udp_socket
        .send_to(&buf_handler.buf[0..buf_handler.get_pos()], (addr, 53))
        .unwrap();

    buf_handler = BufHandler::new();
    packet = DnsPacket::new();

    udp_socket.recv_from(&mut buf_handler.buf).unwrap();
    packet.read(&mut buf_handler)?;

    Ok(packet)
}

fn main() {
    let udp_socket = UdpSocket::bind("0.0.0.0:6969").unwrap();
    let mut buf_handler = BufHandler::new();

    loop {
        let (_, src) = udp_socket.recv_from(&mut buf_handler.buf).unwrap();

        buf_handler.seek(0);
        let mut request_packet = DnsPacket::from_buffer(&mut buf_handler).unwrap();

        let mut response_packet = DnsPacket::new();
        response_packet.header.id = request_packet.header.id;
        response_packet.header.recursion_desired = true;
        response_packet.header.recursion_available = true;
        response_packet.header.authoritative_answer = true;

        let mut packet: DnsPacket = DnsPacket::new();

        if let Some(question) = request_packet.questions.pop() {
            let mut current_address = "202.12.27.33".parse::<Ipv4Addr>().unwrap();

            loop {
                packet = lookup(&question.name, question.qtype, current_address).unwrap();

                if !packet.answers.is_empty() {
                    break;
                }

                for additional in packet.additionals {
                    if let DnsRecord::A { addr, .. } = additional {
                        current_address = addr;
                    }
                }
            }
        }

        for answer in packet.answers {
            response_packet.answers.push(answer);
        }

        buf_handler.seek(0);
        response_packet.write(&mut buf_handler).unwrap();

        udp_socket
            .send_to(&buf_handler.buf[0..buf_handler.get_pos()], src)
            .unwrap();
    }
}
