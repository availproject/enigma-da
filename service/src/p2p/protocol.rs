use std::io;

use crate::p2p::types::{MessageProtocol, MessageRequest, MessageResponse};
use async_trait::async_trait;
use libp2p::futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{
    futures::{AsyncRead, AsyncWrite},
    request_response::Codec,
};

#[async_trait]
impl Codec for MessageProtocol {
    type Protocol = MessageProtocol;
    type Request = MessageRequest;
    type Response = MessageResponse;

    async fn read_request<'a, 'b, 'c, T>(
        &'a mut self,
        _protocol: &'b Self::Protocol,
        io: &'c mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
        T: 'async_trait,
        'a: 'async_trait,
        'b: 'async_trait,
        'c: 'async_trait,
        Self: 'async_trait,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        let request = serde_json::from_slice(&buf);
        request.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    async fn read_response<'a, 'b, 'c, T>(
        &'a mut self,
        _protocol: &'b Self::Protocol,
        io: &'c mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
        T: 'async_trait,
        'a: 'async_trait,
        'b: 'async_trait,
        'c: 'async_trait,
        Self: 'async_trait,
    {
        let mut buf = Vec::new();
        io.read_to_end(&mut buf).await?;
        let response = serde_json::from_slice(&buf);
        response.map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    async fn write_request<'a, 'b, 'c, T>(
        &'a mut self,
        _protocol: &'b Self::Protocol,
        io: &'c mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
        T: 'async_trait,
        'a: 'async_trait,
        'b: 'async_trait,
        'c: 'async_trait,
        Self: 'async_trait,
    {
        let buf = serde_json::to_vec(&req).expect("Failed to serialize request");
        io.write_all(&buf).await?;
        Ok(())
    }

    async fn write_response<'a, 'b, 'c, T>(
        &'a mut self,
        _protocol: &'b Self::Protocol,
        io: &'c mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
        T: 'async_trait,
        'a: 'async_trait,
        'b: 'async_trait,
        'c: 'async_trait,
        Self: 'async_trait,
    {
        let buf = serde_json::to_vec(&res).expect("Failed to serialize response");
        io.write_all(&buf).await?;
        Ok(())
    }
}
