use std::sync::mpsc::{self, Receiver, SyncSender};

const POOL_SIZE: usize = 256;
pub const BUF_SIZE: usize = 1500;

pub struct BufferPool {
    tx: SyncSender<Box<[u8; BUF_SIZE]>>,
    rx: std::sync::Mutex<Receiver<Box<[u8; BUF_SIZE]>>>,
}

impl BufferPool {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            let _ = tx.send(Box::new([0u8; BUF_SIZE]));
        }
        Self {
            tx,
            rx: std::sync::Mutex::new(rx),
        }
    }

    pub fn get(&self) -> PooledBuf {
        let buf = self
            .rx
            .lock()
            .unwrap()
            .try_recv()
            .unwrap_or_else(|_| Box::new([0u8; BUF_SIZE]));
        PooledBuf {
            buf: Some(buf),
            pool_tx: self.tx.clone(),
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new()
    }
}

pub struct PooledBuf {
    buf: Option<Box<[u8; BUF_SIZE]>>,
    pool_tx: SyncSender<Box<[u8; BUF_SIZE]>>,
}

impl PooledBuf {
    pub fn as_slice(&self) -> &[u8] {
        self.buf.as_ref().unwrap().as_ref()
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.buf.as_mut().unwrap().as_mut()
    }
}

impl Drop for PooledBuf {
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            let _ = self.pool_tx.try_send(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_get_returns_buf() {
        let pool = BufferPool::new();
        let buf = pool.get();
        assert_eq!(buf.as_slice().len(), BUF_SIZE);
    }

    #[test]
    fn pool_buf_returns_on_drop() {
        let pool = BufferPool::new();
        {
            let _buf = pool.get();
        }
        // After drop, a new get should still work
        let buf2 = pool.get();
        assert_eq!(buf2.as_slice().len(), BUF_SIZE);
    }

    #[test]
    fn pool_many_bufs() {
        let pool = BufferPool::new();
        let bufs: Vec<_> = (0..300).map(|_| pool.get()).collect();
        assert_eq!(bufs.len(), 300);
    }
}
