use std::str::FromStr;

use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, ResponseCode};
use hickory_proto::rr::rdata::SOA;
use hickory_proto::rr::{Name, RData, Record};
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;

pub(super) async fn send_nxdomain<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
) -> ResponseInfo {
    let soa = soa_record();
    let builder = MessageResponseBuilder::from_message_request(request);
    let metadata = response_metadata(&request.metadata, ResponseCode::NXDomain, true, true);
    let response = builder.build(
        metadata,
        std::iter::empty::<&Record>(),
        std::iter::empty::<&Record>(),
        std::iter::once(&soa),
        std::iter::empty::<&Record>(),
    );
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| fallback_header(&request.metadata, ResponseCode::NXDomain, true, true))
}

pub(super) async fn send_servfail<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let metadata = response_metadata(&request.metadata, ResponseCode::ServFail, false, true);
    let response = builder.build_no_records(metadata);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| fallback_header(&request.metadata, ResponseCode::ServFail, false, true))
}

pub(super) async fn send_refused<R: ResponseHandler>(
    request: &Request,
    mut response_handle: R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let metadata = response_metadata(&request.metadata, ResponseCode::Refused, false, false);
    let response = builder.build_no_records(metadata);
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| fallback_header(&request.metadata, ResponseCode::Refused, false, false))
}

pub(super) async fn send_answer<R: ResponseHandler>(
    request: &Request,
    records: &[Record],
    mut response_handle: R,
) -> ResponseInfo {
    let builder = MessageResponseBuilder::from_message_request(request);
    let metadata = response_metadata(&request.metadata, ResponseCode::NoError, false, true);
    let response = builder.build(
        metadata,
        records.iter(),
        std::iter::empty::<&Record>(),
        std::iter::empty::<&Record>(),
        std::iter::empty::<&Record>(),
    );
    response_handle
        .send_response(response)
        .await
        .unwrap_or_else(|_| fallback_header(&request.metadata, ResponseCode::NoError, false, true))
}

fn response_metadata(
    original: &Metadata,
    response_code: ResponseCode,
    authoritative: bool,
    recursion_available: bool,
) -> Metadata {
    let mut metadata = Metadata::response_from_request(original);
    metadata.message_type = MessageType::Response;
    metadata.response_code = response_code;
    metadata.authoritative = authoritative;
    metadata.recursion_available = recursion_available;
    metadata
}

fn fallback_header(
    original: &Metadata,
    response_code: ResponseCode,
    authoritative: bool,
    recursion_available: bool,
) -> ResponseInfo {
    ResponseInfo::from(Header {
        metadata: response_metadata(original, response_code, authoritative, recursion_available),
        counts: HeaderCounts::default(),
    })
}

fn soa_record() -> Record {
    let name = Name::from_str("outcall.invalid.").unwrap_or_else(|_| Name::root());
    let mname = Name::from_str("ns.outcall.invalid.").unwrap_or_else(|_| Name::root());
    let rname = Name::from_str("hostmaster.outcall.invalid.").unwrap_or_else(|_| Name::root());
    let soa = SOA::new(mname, rname, 1, 3600, 600, 86400, 60);
    Record::from_rdata(name, 60, RData::SOA(soa))
}
