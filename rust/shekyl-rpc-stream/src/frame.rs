// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Where the reader is in the record stream, and whether that is a submission.
//!
//! The stream opens records. This module decides which of those a sender is
//! allowed to send, and whether the records ending here are one submission.
//! The verdict is that decision. It is not a second look at a window of
//! shapes: a window can assemble a padded frame out of the tail of one
//! message and the head of the next.
//!
//! A submission is one of two runs:
//!
//! - a padded frame, at the record that finishes it;
//! - exactly [`SUBMISSION_RECORDS`](crate::SUBMISSION_RECORDS) largest-class
//!   payload records in a row, counted from a message boundary.
//!
//! A boundary is the start of the stream, a record of a smaller class, a
//! padded frame that just finished, or a record this side sent (on the
//! daemon, a response). An empty padding record opens a frame.
//! It does not end the message before it. One more largest-class record
//! after the five clears the verdict, so a longer ordinary message is never
//! a submission. A full-size submission sent straight after a message that
//! ended on a largest-class record, with no response between them, has no
//! boundary in front of it, and the daemon refuses it. Only a pipelining
//! client sends that way.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use shekyl_noise::ClassId;

use super::SUBMISSION_RECORDS;

/// The class of the close record. The table is strictly increasing, so the
/// smallest class is index 0, and nothing else sends occupancy 0 there.
pub(crate) const CLOSE_CLASS: ClassId = ClassId(0);

/// The verdict [`crate::RecordStream`] publishes for the request handler.
///
/// The handler reads it after the body, while hyper owns the stream. It is
/// the reader's decision at the last data record. The close record does not
/// change it.
#[derive(Clone, Debug)]
pub struct InboundShape(Arc<AtomicBool>);

impl Default for InboundShape {
    fn default() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
}

impl InboundShape {
    /// Whether the records ending at the last data record are one submission.
    #[must_use]
    pub fn ends_in_submission(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub(crate) fn set(&self, submission: bool) {
        self.0.store(submission, Ordering::Release);
    }
}

/// A record the reader refuses. The stream reports it as
/// [`crate::RecordShapeRefused`].
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct Refused;

/// What admitting one opened record did.
pub(crate) enum Admit {
    /// Occupancy 0 in [`CLOSE_CLASS`], outside a frame. The stream ends.
    Close,
    /// A record a sender makes. [`Frame::submission`] is the verdict here.
    Data,
}

/// The reader's place. The variants are the combinations that can occur.
enum Place {
    /// No frame is open. `count` is the consecutive largest-class payload
    /// records since a boundary, capped at one past
    /// [`SUBMISSION_RECORDS`](crate::SUBMISSION_RECORDS). That extra one is
    /// a longer ordinary message, and further records stay there so the
    /// count cannot wrap back onto a submission.
    Run { count: usize },
    /// Leading empty largest-class records. The payload has not started.
    Pad { count: usize },
    /// Payload records of an open frame still to accept. At least one.
    Rest { left: usize },
}

/// The cursor. It starts on a boundary, so the first records of a stream
/// can be a submission.
#[derive(Debug)]
pub(crate) struct Frame {
    place: Place,
    submission: bool,
}

impl Frame {
    pub(crate) fn new() -> Self {
        Self {
            place: Place::Run { count: 0 },
            submission: false,
        }
    }

    /// The verdict at the last data record this cursor admitted.
    pub(crate) fn submission(&self) -> bool {
        self.submission
    }

    /// Admit one opened record.
    ///
    /// `empty` is occupancy 0. `largest` is the table's largest class, the
    /// only class padding and a submission's payload use.
    pub(crate) fn admit(
        &mut self,
        class: ClassId,
        empty: bool,
        largest: ClassId,
    ) -> Result<Admit, Refused> {
        if empty && class == CLOSE_CLASS {
            return self.admit_close();
        }
        self.admit_data(class, empty, largest)?;
        Ok(Admit::Data)
    }

    fn admit_close(&mut self) -> Result<Admit, Refused> {
        match self.place {
            Place::Run { .. } => Ok(Admit::Close),
            // The close is outside any submission. Inside a frame it is a
            // record the sender does not make.
            Place::Pad { .. } | Place::Rest { .. } => Err(Refused),
        }
    }

    fn admit_data(&mut self, class: ClassId, empty: bool, largest: ClassId) -> Result<(), Refused> {
        match self.place {
            Place::Pad { count } => self.admit_pad(count, class, empty, largest),
            Place::Rest { left } => self.admit_rest(left, class, empty, largest),
            Place::Run { count } => self.admit_run(count, class, empty, largest),
        }
    }

    fn admit_pad(
        &mut self,
        count: usize,
        class: ClassId,
        empty: bool,
        largest: ClassId,
    ) -> Result<(), Refused> {
        if empty {
            // At most SUBMISSION_RECORDS - 1 padding records, all largest.
            if class != largest || count + 1 >= SUBMISSION_RECORDS {
                return Err(Refused);
            }
            self.place = Place::Pad { count: count + 1 };
            self.submission = false;
            return Ok(());
        }
        if class != largest {
            return Err(Refused);
        }
        // This payload record is one of the frame. What remains after it
        // is the rest of the five, not counting the padding already read.
        self.payload_accepted(SUBMISSION_RECORDS - count - 1);
        Ok(())
    }

    fn admit_rest(
        &mut self,
        left: usize,
        class: ClassId,
        empty: bool,
        largest: ClassId,
    ) -> Result<(), Refused> {
        // Padding after the payload has started, or a smaller record where
        // the frame still owes payload.
        if empty || class != largest {
            return Err(Refused);
        }
        debug_assert!(left >= 1, "a resting frame owes at least this record");
        self.payload_accepted(left - 1);
        Ok(())
    }

    fn admit_run(
        &mut self,
        count: usize,
        class: ClassId,
        empty: bool,
        largest: ClassId,
    ) -> Result<(), Refused> {
        if empty {
            // Padding opens a frame. An empty record of any other class is
            // not one: the smallest class is the close record, already
            // handled, and the middle class is never empty.
            if class != largest {
                return Err(Refused);
            }
            self.place = Place::Pad { count: 1 };
            self.submission = false;
            return Ok(());
        }
        if class == largest {
            // Exactly five, and no further. One past that is a longer
            // ordinary message, or the continuation of one that already
            // ended on a full record. The count stays there.
            let count = count.saturating_add(1).min(SUBMISSION_RECORDS + 1);
            self.submission = count == SUBMISSION_RECORDS;
            self.place = Place::Run { count };
            return Ok(());
        }
        // A smaller class is the tail of an ordinary message, and the
        // boundary the next run is counted from.
        self.submission = false;
        self.place = Place::Run { count: 0 };
        Ok(())
    }

    /// This side sealed a record: on the daemon, its response.
    ///
    /// The peer's message ended before it. A client sends its next request
    /// only after the response, so the next run counts from here, and a
    /// path observer sees the response between them too. Inside a frame
    /// nothing changes: the frame is still owed its records.
    pub(crate) fn sent(&mut self) {
        if let Place::Run { .. } = self.place {
            self.place = Place::Run { count: 0 };
        }
    }

    /// One payload record of a padded frame has been accepted. `remaining`
    /// is how many payload records the frame still owes after this one.
    fn payload_accepted(&mut self, remaining: usize) {
        if remaining == 0 {
            self.submission = true;
            // The finished frame is a boundary. The next largest-class run
            // is counted from zero, not from this frame's payload records.
            self.place = Place::Run { count: 0 };
        } else {
            self.submission = false;
            self.place = Place::Rest { left: remaining };
        }
    }
}

impl std::fmt::Debug for Place {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Run { count } => write!(f, "Run({count})"),
            Self::Pad { count } => write!(f, "Pad({count})"),
            Self::Rest { left } => write!(f, "Rest({left})"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::class_table;

    fn largest() -> ClassId {
        class_table().largest()
    }

    /// Admit `records` as `(class, empty)`. The value is the verdict after
    /// the last data record. A close record leaves the verdict as it was.
    fn drive(records: &[(u8, bool)]) -> Result<bool, Refused> {
        let mut frame = Frame::new();
        let largest = largest();
        for &(class, empty) in records {
            frame.admit(ClassId(class), empty, largest)?;
        }
        Ok(frame.submission())
    }

    fn copies(class: u8, empty: bool, n: usize) -> Vec<(u8, bool)> {
        vec![(class, empty); n]
    }

    #[test]
    fn a_padded_frame_is_a_submission_only_when_it_finishes() {
        let largest = largest().0;
        // Four padding records and one payload record: the common shape.
        let mut run = copies(largest, true, SUBMISSION_RECORDS - 1);
        run.push((largest, false));
        assert!(drive(&run).unwrap());

        // The next largest-class record is a new message. The padding
        // behind it belongs to the frame that already finished.
        run.push((largest, false));
        assert!(!drive(&run).unwrap(), "one record after the frame");

        // Four more largest records would fill a window of five by borrowing
        // that padding. They are still the next message.
        let mut four_after = run;
        four_after.extend(copies(largest, false, SUBMISSION_RECORDS - 2));
        assert!(
            !drive(&four_after).unwrap(),
            "four largest records after a padded frame"
        );
    }

    #[test]
    fn five_largest_records_count_only_from_a_boundary() {
        let largest = largest().0;
        let five = copies(largest, false, SUBMISSION_RECORDS);
        assert!(drive(&five).unwrap(), "the stream starts on a boundary");

        let mut six = five.clone();
        six.push((largest, false));
        assert!(!drive(&six).unwrap(), "a longer run is an ordinary message");

        // A smaller class ends an ordinary message. The five after it count.
        let mut after_small = vec![(0, false)];
        after_small.extend(five.iter().copied());
        assert!(drive(&after_small).unwrap());

        // A message that ended on a full record is not a boundary. The five
        // after it continue that run.
        let mut after_full = copies(largest, false, 1);
        after_full.extend(five.iter().copied());
        assert!(!drive(&after_full).unwrap());
    }

    #[test]
    fn a_finished_frame_is_a_boundary_for_the_next_five() {
        let largest = largest().0;
        let mut run = copies(largest, true, SUBMISSION_RECORDS - 1);
        run.push((largest, false));
        run.extend(copies(largest, false, SUBMISSION_RECORDS));
        assert!(drive(&run).unwrap());
    }

    #[test]
    fn a_record_this_side_sent_is_a_boundary() {
        let largest = largest();
        let mut frame = Frame::new();
        let five_full = |frame: &mut Frame| {
            for _ in 0..SUBMISSION_RECORDS {
                frame.admit(largest, false, largest).unwrap();
            }
            frame.submission()
        };
        assert!(five_full(&mut frame), "the first full-size submission");
        // The daemon answers it. The next five are the next request.
        frame.sent();
        assert!(five_full(&mut frame), "a second one after the response");
        // Without a response between them, the run continues.
        assert!(!five_full(&mut frame), "five more with no response");
        // A response does not change the verdict the handler reads.
        frame.sent();
        assert!(!frame.submission());
    }

    #[test]
    fn a_record_sent_inside_a_frame_leaves_the_frame() {
        let largest = largest();
        let mut frame = Frame::new();
        frame.admit(largest, true, largest).unwrap();
        frame.sent();
        for _ in 1..SUBMISSION_RECORDS {
            frame.admit(largest, false, largest).unwrap();
        }
        assert!(frame.submission(), "the frame the padding opened");
        // And a smaller record where the frame owes payload is still refused.
        let mut frame = Frame::new();
        frame.admit(largest, true, largest).unwrap();
        frame.sent();
        assert!(frame.admit(ClassId(0), false, largest).is_err());
    }

    #[test]
    fn a_sender_shape_is_the_only_one_admitted() {
        let largest = largest().0;
        let refused = |records: &[(u8, bool)]| assert!(drive(records).is_err(), "{records:?}");

        // A fifth padding record. A submission carries payload.
        refused(&copies(largest, true, SUBMISSION_RECORDS));
        // An empty record in the middle class.
        refused(&[(1, true)]);
        // Padding, then a smaller payload record.
        refused(&[(largest, true), (0, false)]);
        // Padding after the payload has started: one pad, one payload, a pad.
        refused(&[(largest, true), (largest, false), (largest, true)]);
        // The close inside a frame.
        refused(&[(largest, true), (0, true)]);
        // A frame that owes payload gets a smaller record.
        refused(&[
            (largest, true),
            (largest, true),
            (largest, false),
            (0, false),
        ]);

        // The close after an ordinary record is the end, and it is not itself
        // a submission.
        assert!(!drive(&[(0, false), (0, true)]).unwrap());
    }
}
