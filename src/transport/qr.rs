use crate::error::{HwSignerError, Result};

/// QR code-based transport for air-gapped hardware wallets.
///
/// Uses animated QR codes (UR/BCR standard) to exchange data between
/// the companion software and an air-gapped signing device.
///
/// The flow is:
/// 1. Companion encodes the signing request as a series of QR codes
/// 2. Air-gapped device scans the QR codes with its camera
/// 3. Device signs and displays response as QR codes
/// 4. Companion scans the response QR codes
///
/// This transport does NOT implement the [`crate::transport::Transport`]
/// trait directly since the communication model is fundamentally different
/// (display + scan vs stream). Instead, it provides encode/decode helpers
/// for use with the [`crate::protocol::HwpCodec`].
pub struct QrTransport {
    /// Maximum bytes per QR code frame.
    max_fragment_size: usize,
}

/// A single QR code frame in an animated sequence.
#[derive(Debug, Clone)]
pub struct QrFrame {
    /// Frame index (0-based).
    pub index: usize,
    /// Total number of frames in the sequence.
    pub total: usize,
    /// Raw payload bytes for this frame.
    pub data: Vec<u8>,
}

impl QrTransport {
    /// Create a new QR transport.
    ///
    /// `max_fragment_size` controls how many bytes fit in each QR code.
    /// Typical values: 200 bytes for QR version 10, 400 for version 15.
    pub fn new(max_fragment_size: usize) -> Self {
        Self { max_fragment_size }
    }

    /// Encode a payload into a sequence of QR frames.
    ///
    /// If the payload fits in a single QR code, returns one frame.
    /// Otherwise, splits into animated QR code sequence.
    pub fn encode_frames(&self, payload: &[u8]) -> Vec<QrFrame> {
        let total = (payload.len() + self.max_fragment_size - 1) / self.max_fragment_size;
        let total = total.max(1);

        payload
            .chunks(self.max_fragment_size)
            .enumerate()
            .map(|(i, chunk)| QrFrame {
                index: i,
                total,
                data: chunk.to_vec(),
            })
            .collect()
    }

    /// Reassemble a complete payload from QR frames.
    ///
    /// Frames can arrive in any order. Returns `None` if frames are
    /// missing or inconsistent.
    pub fn decode_frames(&self, frames: &[QrFrame]) -> Result<Vec<u8>> {
        if frames.is_empty() {
            return Err(HwSignerError::ProtocolError("No QR frames received".into()));
        }

        let total = frames[0].total;
        if frames.len() != total {
            return Err(HwSignerError::ProtocolError(format!(
                "Expected {} QR frames, got {}",
                total,
                frames.len()
            )));
        }

        // Sort by index and concatenate
        let mut sorted: Vec<&QrFrame> = frames.iter().collect();
        sorted.sort_by_key(|f| f.index);

        let mut payload = Vec::new();
        for (expected_idx, frame) in sorted.iter().enumerate() {
            if frame.index != expected_idx {
                return Err(HwSignerError::ProtocolError(format!(
                    "Missing QR frame index {}",
                    expected_idx
                )));
            }
            payload.extend_from_slice(&frame.data);
        }

        Ok(payload)
    }

    /// Encode a single QR frame as a QR code image (PNG bytes).
    ///
    /// The frame is prefixed with a 4-byte header: [index:2 LE][total:2 LE]
    /// followed by the raw data.
    #[cfg(feature = "qr")]
    pub fn frame_to_png(&self, frame: &QrFrame, pixel_size: u32) -> Result<Vec<u8>> {
        use qrcode::QrCode;

        let mut encoded = Vec::with_capacity(4 + frame.data.len());
        encoded.extend_from_slice(&(frame.index as u16).to_le_bytes());
        encoded.extend_from_slice(&(frame.total as u16).to_le_bytes());
        encoded.extend_from_slice(&frame.data);

        let code = QrCode::new(&encoded)
            .map_err(|e| HwSignerError::TransportError(format!("QR encode failed: {}", e)))?;

        let image = code.render::<image::Luma<u8>>()
            .quiet_zone(true)
            .module_dimensions(pixel_size, pixel_size)
            .build();

        let mut png_bytes = Vec::new();
        let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
        image::ImageEncoder::write_image(
            encoder,
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::L8,
        )
        .map_err(|e| HwSignerError::TransportError(format!("PNG encode failed: {}", e)))?;

        Ok(png_bytes)
    }
}
