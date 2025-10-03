use std::net::Ipv4Addr;
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
        let mut cur_pos = 0;

        loop {
            let part_length = self.read()?;

            if part_length == 0 {
                if cur_pos != 0 {
                    self.seek(cur_pos);
                }
                break;
            }

            if part_length & 0xC0 == 0xC0 {
                let jump_pos = (((part_length & 0x3F) as u16) << 8) | (self.read()? as u16);
                cur_pos = self.get_pos();
                self.seek(jump_pos as usize);
            } else {
                out.push_str(&delim);
                let end_index = self.pos + (part_length as usize);
                let arr_slice = self.buf[self.pos..end_index]
                    .try_into()
                    .expect("Cannot slice the data");
                self.pos = end_index as usize;
                out.push_str(&String::from_utf8_lossy(arr_slice).to_lowercase());
                delim = ".";
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
        self.recursion_desired = (a & 0x1) == 1;

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
    A = 1,
    UNKNOWN,
}

impl QueryType {
    fn from_num(num: u8) -> QueryType {
        match num {
            1 => QueryType::A,
            _ => QueryType::UNKNOWN,
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
        self.qtype = QueryType::from_num(buf_handler.read_u16()? as u8);
        let _qclass = buf_handler.read_u16()?;
        Ok(())
    }

    fn write(&self, buf_handler: &mut BufHandler) -> Result<(), String> {
        buf_handler.write_qname(&self.name)?;
        buf_handler.write_u16(self.qtype as u16)?;
        buf_handler.write_u16(1)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Clone)]
enum DnsRecord {
    UNKOWN,
    A {
        domain: String,
        ip: Ipv4Addr,
        ttl: u32,
    },
}

impl DnsRecord {
    fn read(buf_handler: &mut BufHandler) -> Result<DnsRecord, String> {
        let mut qname = String::new();
        buf_handler.read_qname(&mut qname)?;
        let qtype = QueryType::from_num(buf_handler.read_u16()? as u8);
        let qclass = buf_handler.read_u16()?;
        let ttl = buf_handler.read_u32()?;
        let len = buf_handler.read_u16()?;

        match qtype {
            QueryType::A => Ok(DnsRecord::A {
                domain: qname,
                ip: Ipv4Addr::new(
                    buf_handler.read()?,
                    buf_handler.read()?,
                    buf_handler.read()?,
                    buf_handler.read()?,
                ),
                ttl: ttl,
            }),
            _ => Ok(DnsRecord::UNKOWN),
        }
    }

    fn write(&self, buf_handler: &mut BufHandler) -> Result<(), String> {
        match *self {
            DnsRecord::A {
                ref domain,
                ref ip,
                ttl,
            } => {
                buf_handler.write_qname(domain)?;
                buf_handler.write_u16(QueryType::A as u16)?;
                buf_handler.write_u16(1)?;
                buf_handler.write_u32(ttl)?;
                buf_handler.write_u16(4)?;

                let octets = ip.octets();
                buf_handler.write(octets[0])?;
                buf_handler.write(octets[1])?;
                buf_handler.write(octets[2])?;
                buf_handler.write(octets[3])?;
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

fn main() {
    let mut buf_reader = BufHandler::new();

    let mut dns_packet = DnsPacket::new();
    dns_packet.header.id = 6262;
    dns_packet.header.recursion_desired = true;
    dns_packet.questions.push(DnsQuestion {
        name: "animeshdhakal.com.np".to_string(),
        qtype: QueryType::A,
    });

    dns_packet.write(&mut buf_reader).unwrap();

    let udp_socket = UdpSocket::bind("0.0.0.0:6969").unwrap();

    // udp_socket
    //     .send_to(&buf_reader.buf, ("8.8.8.8", 53))
    //     .unwrap();

    buf_reader = BufHandler::new();
    dns_packet = DnsPacket::new();

    let (size, src) = udp_socket.recv_from(&mut buf_reader.buf).unwrap();
    dns_packet.read(&mut buf_reader).unwrap();

    udp_socket.send_to(&buf_reader.buf, &src).unwrap();

    println!("{:#?}", dns_packet);
}
