use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn empty_io_slices() {
    {
        // next_slice
        assert_eq!(EmptyIoSlices::default().next_slice(None).unwrap(), None);
        assert_eq!(EmptyIoSlices::default().next_slice(Some(1)).unwrap(), None);
    }
    {
        // skip
        assert!(matches!(
            EmptyIoSlices::default().skip(1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
        EmptyIoSlices::default().skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // two empty iterators are equal
        assert_ne!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // empty vs non-empty should not be equal
        let buf = [1u8, 2, 3];
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(SingletonIoSlice::new(&buf))
                .unwrap()
                .unwrap(),
            0
        );
        // non-empty vs empty should not be equal
        assert_eq!(
            SingletonIoSlice::new(&buf)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn zero_filled_io_slices() {
    const LEN: usize = ZeroFilledIoSlices::CHUNK_SIZE * 2 + 3;
    {
        // next_slice
        let mut iter = ZeroFilledIoSlices::new(LEN);
        let expected = [0u8; ZeroFilledIoSlices::CHUNK_SIZE];
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &expected);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than chunk
        let mut iter = ZeroFilledIoSlices::new(5);
        assert_eq!(iter.next_slice(Some(3)).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &[0u8; 2]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than chunk size
        let mut iter = ZeroFilledIoSlices::new(LEN);
        let expected = [0u8; ZeroFilledIoSlices::CHUNK_SIZE];
        assert_eq!(iter.next_slice(Some(LEN + 3)).unwrap().unwrap(), &expected);
        assert_eq!(iter.next_slice(Some(LEN)).unwrap().unwrap(), &expected);
        assert_eq!(iter.next_slice(Some(LEN)).unwrap().unwrap(), &[0u8; 3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty
        let mut iter = ZeroFilledIoSlices::new(0);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut iter = ZeroFilledIoSlices::new(LEN);
        iter.skip(LEN).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut iter = ZeroFilledIoSlices::new(LEN);
        iter.skip(ZeroFilledIoSlices::CHUNK_SIZE + 1).unwrap();
        // remaining: CHUNK_SIZE + 2 bytes = one full chunk + 2
        let expected_full = [0u8; ZeroFilledIoSlices::CHUNK_SIZE];
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &expected_full);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &[0u8; 2]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        assert!(matches!(
            ZeroFilledIoSlices::new(LEN).skip(LEN + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut iter = ZeroFilledIoSlices::new(LEN);
        iter.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal length zero-filled iterators are equal
        assert_ne!(
            ZeroFilledIoSlices::new(LEN)
                .ct_eq_with_iter(ZeroFilledIoSlices::new(LEN))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths are not equal
        assert_eq!(
            ZeroFilledIoSlices::new(LEN)
                .ct_eq_with_iter(ZeroFilledIoSlices::new(LEN + 1))
                .unwrap()
                .unwrap(),
            0
        );
        // zero-filled vs empty
        assert_eq!(
            ZeroFilledIoSlices::new(LEN)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // empty vs zero-filled
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(ZeroFilledIoSlices::new(LEN))
                .unwrap()
                .unwrap(),
            0
        );
        // both zero-length
        assert_ne!(
            ZeroFilledIoSlices::new(0)
                .ct_eq_with_iter(ZeroFilledIoSlices::new(0))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn singleton_io_slice() {
    let buf = [1u8, 2, 3, 4, 5];
    {
        // next_slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_slice(Some(3)).unwrap().unwrap(), &buf[..3]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &buf[3..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &buf);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty slice
        // Empty slices are omitted
        let mut iter = SingletonIoSlice::new(&[]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip(buf.len()).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip(2).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf[2..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        assert!(matches!(
            SingletonIoSlice::new(&buf).skip(buf.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal slices are equal
        assert_ne!(
            SingletonIoSlice::new(&buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf))
                .unwrap()
                .unwrap(),
            0
        );
        // different content is not equal
        let buf2 = [1u8, 2, 3, 4, 6];
        assert_eq!(
            SingletonIoSlice::new(&buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf2))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths are not equal
        assert_eq!(
            SingletonIoSlice::new(&buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf[..3]))
                .unwrap()
                .unwrap(),
            0
        );
        // singleton vs empty
        assert_eq!(
            SingletonIoSlice::new(&buf)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // empty vs singleton
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(SingletonIoSlice::new(&buf))
                .unwrap()
                .unwrap(),
            0
        );
        // both empty slices
        assert_ne!(
            SingletonIoSlice::new(&[])
                .ct_eq_with_iter(SingletonIoSlice::new(&[]))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn buffers_slice_io_slices_iter() {
    let buf1 = [1u8, 2];
    let buf2 = [3u8, 4, 5, 6, 7];
    let slices = [buf1.as_slice(), buf2.as_slice()];
    {
        // next_slice
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than first buffer
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &buf1[..1]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than buffers
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len spanning across buffers
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_slice(Some(4)).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(Some(4)).unwrap().unwrap(), &buf2[..4]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2[4..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty slices
        let empty: [&[u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesIter::new(&empty);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let slices_with_empty = [buf1.as_slice(), &[], buf2.as_slice()];
        let mut iter = BuffersSliceIoSlicesIter::new(&slices_with_empty);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        IoSlicesIter::skip(&mut iter, buf1.len() + buf2.len()).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle of first buffer
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        IoSlicesIter::skip(&mut iter, 1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip across buffer boundary
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        IoSlicesIter::skip(&mut iter, buf1.len() + 2).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2[2..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert!(matches!(
            IoSlicesIter::skip(&mut iter, buf1.len() + buf2.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        IoSlicesIter::skip(&mut iter, 0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal slices are equal
        assert_ne!(
            BuffersSliceIoSlicesIter::new(&slices)
                .ct_eq_with_iter(BuffersSliceIoSlicesIter::new(&slices))
                .unwrap()
                .unwrap(),
            0
        );
        // equal content in different layout
        let combined = [1u8, 2, 3, 4, 5, 6, 7];
        assert_ne!(
            BuffersSliceIoSlicesIter::new(&slices)
                .ct_eq_with_iter(SingletonIoSlice::new(&combined))
                .unwrap()
                .unwrap(),
            0
        );
        // different content
        let buf2_diff = [3u8, 4, 5, 6, 8];
        let slices_diff = [buf1.as_slice(), buf2_diff.as_slice()];
        assert_eq!(
            BuffersSliceIoSlicesIter::new(&slices)
                .ct_eq_with_iter(BuffersSliceIoSlicesIter::new(&slices_diff))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths
        assert_eq!(
            BuffersSliceIoSlicesIter::new(&slices)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf1))
                .unwrap()
                .unwrap(),
            0
        );
        // vs empty
        assert_eq!(
            BuffersSliceIoSlicesIter::new(&slices)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // empty vs buffers
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(BuffersSliceIoSlicesIter::new(&slices))
                .unwrap()
                .unwrap(),
            0
        );
        // both empty
        let empty: [&[u8]; 0] = [];
        assert_ne!(
            BuffersSliceIoSlicesIter::new(&empty)
                .ct_eq_with_iter(BuffersSliceIoSlicesIter::new(&empty))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn io_slices_iter_chain() {
    let buf1 = [1u8, 2, 3];
    let buf2 = [4u8, 5, 6, 7, 8];
    {
        // next_slice
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len within first iterator
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_slice(Some(2)).unwrap().unwrap(), &buf1[..2]);
        assert_eq!(chain.next_slice(Some(10)).unwrap().unwrap(), &buf1[2..]);
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len spanning across iterators
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_slice(Some(5)).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_slice(Some(5)).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than both
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_slice(Some(100)).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_slice(Some(100)).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // chain with empty first
        let mut chain = EmptyIoSlices::default().chain(SingletonIoSlice::new(&buf1));
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // chain with empty second
        let mut chain = SingletonIoSlice::new(&buf1).chain(EmptyIoSlices::default());
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // chain of two empties
        let mut chain = EmptyIoSlices::default().chain(EmptyIoSlices::default());
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip(buf1.len() + buf2.len()).unwrap();
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // skip within first iterator
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip(1).unwrap();
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // skip across iterator boundary
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip(buf1.len() + 2).unwrap();
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf2[2..]);
        assert_eq!(chain.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert!(matches!(
            chain.skip(buf1.len() + buf2.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal chains are equal
        assert_ne!(
            SingletonIoSlice::new(&buf1)
                .chain(SingletonIoSlice::new(&buf2))
                .ct_eq_with_iter(SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2)))
                .unwrap()
                .unwrap(),
            0
        );
        // equal content in different layout
        let combined = [1u8, 2, 3, 4, 5, 6, 7, 8];
        assert_ne!(
            SingletonIoSlice::new(&buf1)
                .chain(SingletonIoSlice::new(&buf2))
                .ct_eq_with_iter(SingletonIoSlice::new(&combined))
                .unwrap()
                .unwrap(),
            0
        );
        // different content
        let buf2_diff = [4u8, 5, 6, 7, 9];
        assert_eq!(
            SingletonIoSlice::new(&buf1)
                .chain(SingletonIoSlice::new(&buf2))
                .ct_eq_with_iter(SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2_diff)))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths
        assert_eq!(
            SingletonIoSlice::new(&buf1)
                .chain(SingletonIoSlice::new(&buf2))
                .ct_eq_with_iter(SingletonIoSlice::new(&buf1))
                .unwrap()
                .unwrap(),
            0
        );
        // vs empty
        assert_eq!(
            SingletonIoSlice::new(&buf1)
                .chain(SingletonIoSlice::new(&buf2))
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // empty vs chain
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2)))
                .unwrap()
                .unwrap(),
            0
        );
        // both empty chains
        assert_ne!(
            EmptyIoSlices::default()
                .chain(EmptyIoSlices::default())
                .ct_eq_with_iter(EmptyIoSlices::default().chain(EmptyIoSlices::default()))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn io_slices_iter_take_exact() {
    let buf = [1u8, 2, 3, 4, 5, 6, 7, 8];
    {
        // next_slice
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        assert_eq!(take.next_slice(None).unwrap().unwrap(), &buf[..5]);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than remaining
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        assert_eq!(take.next_slice(Some(3)).unwrap().unwrap(), &buf[..3]);
        assert_eq!(take.next_slice(Some(10)).unwrap().unwrap(), &buf[3..5]);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than remaining
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        assert_eq!(take.next_slice(Some(100)).unwrap().unwrap(), &buf[..5]);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // take_exact(0)
        let mut take = SingletonIoSlice::new(&buf).take_exact(0);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // take_exact larger than underlying iterator errors
        let mut take = SingletonIoSlice::new(&buf[..3]).take_exact(5);
        assert_eq!(take.next_slice(None).unwrap().unwrap(), &buf[..3]);
        assert!(take.next_slice(None).is_err());
    }
    {
        // take_exact over multiple buffers
        let buf1 = [1u8, 2];
        let buf2 = [3u8, 4, 5, 6, 7];
        let slices = [buf1.as_slice(), buf2.as_slice()];
        let mut take = BuffersSliceIoSlicesIter::new(&slices).take_exact(4);
        assert_eq!(take.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(take.next_slice(None).unwrap().unwrap(), &buf2[..2]);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        take.skip(5).unwrap();
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        take.skip(2).unwrap();
        assert_eq!(take.next_slice(None).unwrap().unwrap(), &buf[2..5]);
        assert_eq!(take.next_slice(None).unwrap(), None);
    }
    {
        // skip past take_exact limit
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        assert!(matches!(
            take.skip(6),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut take = SingletonIoSlice::new(&buf).take_exact(5);
        take.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal take_exacts are equal
        assert_ne!(
            SingletonIoSlice::new(&buf)
                .take_exact(5)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf).take_exact(5))
                .unwrap()
                .unwrap(),
            0
        );
        // equal content from different sources
        assert_ne!(
            SingletonIoSlice::new(&buf)
                .take_exact(5)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf[..5]).take_exact(5))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths are not equal
        assert_eq!(
            SingletonIoSlice::new(&buf)
                .take_exact(5)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf).take_exact(3))
                .unwrap()
                .unwrap(),
            0
        );
        // take_exact(0) vs take_exact(0)
        assert_ne!(
            SingletonIoSlice::new(&buf)
                .take_exact(0)
                .ct_eq_with_iter(SingletonIoSlice::new(&buf).take_exact(0))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn covariant_io_slices_iter_ref() {
    let buf = [1u8, 2, 3, 4, 5, 6, 7, 8];
    {
        // next_slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice(Some(3)).unwrap().unwrap(), &buf[..3]);
        assert_eq!(covariant.next_slice(Some(100)).unwrap().unwrap(), &buf[3..]);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice(Some(100)).unwrap().unwrap(), &buf);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // advancing covariant ref advances the original
        let mut inner = SingletonIoSlice::new(&buf);
        {
            let mut covariant = inner.as_ref();
            assert_eq!(covariant.next_slice(Some(3)).unwrap().unwrap(), &buf[..3]);
        }
        // inner should now be advanced past the first 3 bytes
        assert_eq!(inner.next_slice(None).unwrap().unwrap(), &buf[3..]);
        assert_eq!(inner.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty
        let mut inner = SingletonIoSlice::new(&[]);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip(buf.len()).unwrap();
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip(3).unwrap();
        assert_eq!(covariant.next_slice(None).unwrap().unwrap(), &buf[3..]);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert!(matches!(
            covariant.skip(buf.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal refs are equal
        let mut inner1 = SingletonIoSlice::new(&buf);
        let mut inner2 = SingletonIoSlice::new(&buf);
        assert_ne!(inner1.as_ref().ct_eq_with_iter(inner2.as_ref()).unwrap().unwrap(), 0);
        // different content
        let buf2 = [1u8, 2, 3, 4, 5, 6, 7, 9];
        let mut inner1 = SingletonIoSlice::new(&buf);
        let mut inner2 = SingletonIoSlice::new(&buf2);
        assert_eq!(inner1.as_ref().ct_eq_with_iter(inner2.as_ref()).unwrap().unwrap(), 0);
        // different lengths
        let mut inner1 = SingletonIoSlice::new(&buf);
        let mut inner2 = SingletonIoSlice::new(&buf[..3]);
        assert_eq!(inner1.as_ref().ct_eq_with_iter(inner2.as_ref()).unwrap().unwrap(), 0);
        // vs empty
        let mut inner1 = SingletonIoSlice::new(&buf);
        assert_eq!(
            inner1
                .as_ref()
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // both empty
        let mut inner1 = SingletonIoSlice::new(&[]);
        let mut inner2 = SingletonIoSlice::new(&[]);
        assert_ne!(inner1.as_ref().ct_eq_with_iter(inner2.as_ref()).unwrap().unwrap(), 0);
    }
}

/// Test sub-function that exercises the IoSlicesIter trait on GenericIoSlicesIter,
/// with and without a head slice.
/// This function is called from `generic_io_slices_iter` test proper.
fn test_generic_io_slices_iter_variant(
    head: Option<&[u8]>,
    buf1: &[u8],
    buf2: &[u8],
    expected_slices: &[&[u8]],
    combined: &[u8],
) {
    let bufs = [Ok::<_, convert::Infallible>(buf1), Ok(buf2)];
    let make_iter = || GenericIoSlicesIter::new(bufs.clone().into_iter(), head);

    let total_len = combined.len();
    let first = expected_slices[0];

    {
        // next_slice
        let mut iter = make_iter();
        for expected in expected_slices {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than first slice
        let mut iter = make_iter();
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &first[..1]);
        assert_eq!(iter.next_slice(Some(first.len())).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than slices
        let mut iter = make_iter();
        for expected in expected_slices {
            assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut iter = make_iter();
        iter.skip(total_len).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle of first slice
        let mut iter = make_iter();
        iter.skip(1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip across slice boundary
        let mut iter = make_iter();
        iter.skip(first.len() + 1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &expected_slices[1][1..]);
        for expected in &expected_slices[2..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut iter = make_iter();
        assert!(matches!(
            iter.skip(total_len + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut iter = make_iter();
        iter.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal iterators are equal
        assert_ne!(make_iter().ct_eq_with_iter(make_iter()).unwrap().unwrap(), 0);
        // equal content in different layout
        assert_ne!(
            make_iter()
                .ct_eq_with_iter(SingletonIoSlice::new(&combined))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths are not equal
        assert_eq!(
            make_iter()
                .ct_eq_with_iter(SingletonIoSlice::new(first))
                .unwrap()
                .unwrap(),
            0
        );
        // vs empty
        assert_eq!(
            make_iter().ct_eq_with_iter(EmptyIoSlices::default()).unwrap().unwrap(),
            0
        );
        // empty vs generic
        assert_eq!(
            EmptyIoSlices::default().ct_eq_with_iter(make_iter()).unwrap().unwrap(),
            0
        );
    }
}

#[test]
fn generic_io_slices_iter() {
    let buf1 = [1u8, 2, 3];
    let buf2 = [4u8, 5, 6, 7, 8];
    let head_buf = [9u8, 10];

    // without head
    test_generic_io_slices_iter_variant(
        None,
        &buf1,
        &buf2,
        &[buf1.as_slice(), buf2.as_slice()],
        &[1, 2, 3, 4, 5, 6, 7, 8],
    );

    // with head
    test_generic_io_slices_iter_variant(
        Some(&head_buf),
        &buf1,
        &buf2,
        &[head_buf.as_slice(), buf1.as_slice(), buf2.as_slice()],
        &[9, 10, 1, 2, 3, 4, 5, 6, 7, 8],
    );

    {
        // next_slice on empty
        let mut iter = GenericIoSlicesIter::new([Ok::<&[u8], convert::Infallible>(&[]); 0].into_iter(), None);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let bufs = [
            Ok::<_, convert::Infallible>(buf1.as_slice()),
            Ok(&[]),
            Ok(buf2.as_slice()),
        ];
        let mut iter = GenericIoSlicesIter::new(bufs.into_iter(), None);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // different content
        let buf2_diff = [4u8, 5, 6, 7, 9];
        let bufs = [Ok::<_, convert::Infallible>(buf1.as_slice()), Ok(buf2.as_slice())];
        let bufs_diff = [Ok::<_, convert::Infallible>(buf1.as_slice()), Ok(buf2_diff.as_slice())];
        assert_eq!(
            GenericIoSlicesIter::new(bufs.into_iter(), None)
                .ct_eq_with_iter(GenericIoSlicesIter::new(bufs_diff.into_iter(), None))
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // both empty
        let empty_iter1 = GenericIoSlicesIter::new([Ok::<&[u8], convert::Infallible>(&[]); 0].into_iter(), None);
        let empty_iter2 = GenericIoSlicesIter::new([Ok::<&[u8], convert::Infallible>(&[]); 0].into_iter(), None);
        assert_ne!(empty_iter1.ct_eq_with_iter(empty_iter2).unwrap().unwrap(), 0);
    }
}

#[test]
fn singleton_io_slice_mut() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_slice (read path)
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_slice(Some(3)).unwrap().unwrap(), &src[..3]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &src[3..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), &src);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty
        let mut buf = [0u8; 0];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip(src.len()).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip(2).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src[2..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert!(matches!(
            iter.skip(src.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter
        // equal content
        let mut buf = src;
        assert_ne!(
            SingletonIoSliceMut::new(&mut buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&src))
                .unwrap()
                .unwrap(),
            0
        );
        // different content
        let mut buf = src;
        let other = [1u8, 2, 3, 4, 6];
        assert_eq!(
            SingletonIoSliceMut::new(&mut buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&other))
                .unwrap()
                .unwrap(),
            0
        );
        // different lengths
        let mut buf = src;
        assert_eq!(
            SingletonIoSliceMut::new(&mut buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&src[..3]))
                .unwrap()
                .unwrap(),
            0
        );
        // vs empty
        let mut buf = src;
        assert_eq!(
            SingletonIoSliceMut::new(&mut buf)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
        // both empty
        let mut buf = [0u8; 0];
        assert_ne!(
            SingletonIoSliceMut::new(&mut buf)
                .ct_eq_with_iter(SingletonIoSlice::new(&[]))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

/// Helper to test GenericIoSlicesMutIter with a given head configuration.
/// Uses const generics so that array copies work without alloc.
fn test_generic_io_slices_mut_iter_variant(with_head: bool) {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5];
    let head_buf = [98u8, 99];

    let head_src = if with_head { Some(head_buf) } else { None };
    let expected_slices: &[&[u8]] = if with_head {
        &[head_buf.as_ref(), src1.as_ref(), src2.as_ref()]
    } else {
        &[src1.as_ref(), src2.as_ref()]
    };
    let combined_with_head = [98u8, 99, 1, 2, 3, 4, 5];
    let combined_without_head = [1u8, 2, 3, 4, 5];
    let combined: &[u8] = if with_head {
        &combined_with_head
    } else {
        &combined_without_head
    };

    fn ok_mut(s: &mut [u8]) -> Result<&mut [u8], convert::Infallible> {
        Ok(s)
    }

    fn head_mut(h: &mut Option<[u8; 2]>) -> Option<&mut [u8]> {
        h.as_mut().map(|h| h.as_mut_slice())
    }

    // Scratch buffer size for copy_from_iter and ct_eq tests.
    // Must be >= total_len; assert below to catch mismatches.
    const SCRATCH_LEN: usize = 16;

    let total_len = combined.len();
    assert!(total_len <= SCRATCH_LEN);
    let first = expected_slices[0];

    {
        // next_slice (read path): iterate all slices
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        for expected in expected_slices {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than first slice (=head if present)
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &first[..1]);
        assert_eq!(iter.next_slice(Some(first.len())).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than slices
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        for expected in expected_slices {
            assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        iter.skip(total_len).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle of first slice
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        iter.skip(1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &first[1..]);
        for expected in &expected_slices[1..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip across slice boundary
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        iter.skip(first.len() + 1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &expected_slices[1][1..]);
        for expected in &expected_slices[2..] {
            assert_eq!(iter.next_slice(None).unwrap().unwrap(), *expected);
        }
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        assert!(matches!(
            iter.skip(total_len + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        iter.skip(0).unwrap();
    }
    {
        // ct_eq_with_iter - equal content
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        assert_ne!(
            GenericIoSlicesMutIter::new(
                [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
                head_mut(&mut h),
            )
            .ct_eq_with_iter(SingletonIoSlice::new(combined))
            .unwrap()
            .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - different content
        let mut diff = [0u8; SCRATCH_LEN];
        diff[..total_len].copy_from_slice(combined);
        diff[total_len - 1] ^= 0xFF;
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        assert_eq!(
            GenericIoSlicesMutIter::new(
                [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
                head_mut(&mut h),
            )
            .ct_eq_with_iter(SingletonIoSlice::new(&diff[..total_len]))
            .unwrap()
            .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - different lengths
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        assert_eq!(
            GenericIoSlicesMutIter::new(
                [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
                head_mut(&mut h),
            )
            .ct_eq_with_iter(SingletonIoSlice::new(first))
            .unwrap()
            .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - vs empty
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        assert_eq!(
            GenericIoSlicesMutIter::new(
                [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
                head_mut(&mut h),
            )
            .ct_eq_with_iter(EmptyIoSlices::default())
            .unwrap()
            .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - empty vs this
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(GenericIoSlicesMutIter::new(
                    [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
                    head_mut(&mut h),
                ))
                .unwrap()
                .unwrap(),
            0
        );
    }
}

#[test]
fn generic_io_slices_mut_iter() {
    fn ok_mut(s: &mut [u8]) -> Result<&mut [u8], convert::Infallible> {
        Ok(s)
    }

    // without head
    test_generic_io_slices_mut_iter_variant(false);

    // with head
    test_generic_io_slices_mut_iter_variant(true);

    {
        // next_slice on empty iterator
        let empty: [Result<&mut [u8], convert::Infallible>; 0] = [];
        let mut iter = GenericIoSlicesMutIter::new(empty.into_iter(), None);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let mut b1 = [1u8, 2];
        let mut empty = [0u8; 0];
        let mut b2 = [3u8, 4, 5];
        let mut iter = GenericIoSlicesMutIter::new(
            [
                ok_mut(b1.as_mut_slice()),
                ok_mut(empty.as_mut_slice()),
                ok_mut(b2.as_mut_slice()),
            ]
            .into_iter(),
            None,
        );
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &[1u8, 2]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &[3u8, 4, 5]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
}

#[test]
fn io_slices_iter_map_err() {
    let buf1 = [1u8, 2];
    let buf2 = [3u8, 4, 5];
    let slices = [buf1.as_slice(), buf2.as_slice()];
    let combined = [1u8, 2, 3, 4, 5];
    let total_len = combined.len();
    let map_fn = |e: convert::Infallible| -> convert::Infallible { match e {} };
    {
        // next_slice passes through
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &buf1[..1]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        iter.skip(total_len).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        iter.skip(1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1[1..]);
    }
    {
        // skip past end
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert!(matches!(
            iter.skip(total_len + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // ct_eq_with_iter - equal
        assert_ne!(
            BuffersSliceIoSlicesIter::new(&slices)
                .map_err(map_fn)
                .ct_eq_with_iter(SingletonIoSlice::new(&combined))
                .unwrap()
                .unwrap(),
            0
        );
        // ct_eq_with_iter - different
        let diff = [1u8, 2, 3, 4, 9];
        assert_eq!(
            BuffersSliceIoSlicesIter::new(&slices)
                .map_err(map_fn)
                .ct_eq_with_iter(SingletonIoSlice::new(&diff))
                .unwrap()
                .unwrap(),
            0
        );
        // ct_eq_with_iter - vs empty
        assert_eq!(
            BuffersSliceIoSlicesIter::new(&slices)
                .map_err(map_fn)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // IoSlicesIterCommon: next_slice_len, is_empty
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_slice_len().unwrap(), buf1.len());
        assert!(!iter.is_empty().unwrap());
        iter.skip(total_len).unwrap();
        assert_eq!(iter.next_slice_len().unwrap(), 0);
        assert!(iter.is_empty().unwrap());
    }
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5];
    let combined = [1u8, 2, 3, 4, 5];
    let total_len = combined.len();
    {
        // next_slice (read path)
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len smaller than first buffer
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &src1[..1]);
        assert_eq!(iter.next_slice(Some(10)).unwrap().unwrap(), &src1[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice with max_len larger than buffers
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_slice(Some(100)).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // next_slice on empty
        let mut slices: [&mut [u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let mut b1 = src1;
        let mut empty = [0u8; 0];
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), empty.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip all
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        IoSlicesIter::skip(&mut iter, total_len).unwrap();
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip to middle of first buffer
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        IoSlicesIter::skip(&mut iter, 1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src1[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip across buffer boundary
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        IoSlicesIter::skip(&mut iter, src1.len() + 1).unwrap();
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src2[1..]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip past end
        let mut b1 = src1;
        let mut slices = [b1.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert!(matches!(
            IoSlicesIter::skip(&mut iter, src1.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip(0)
        let mut slices: [&mut [u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        IoSlicesIter::skip(&mut iter, 0).unwrap();
    }
    {
        // ct_eq_with_iter - equal
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        assert_ne!(
            BuffersSliceIoSlicesMutIter::new(&mut slices)
                .ct_eq_with_iter(SingletonIoSlice::new(&combined))
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - different content
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let diff = [1u8, 2, 3, 4, 9];
        assert_eq!(
            BuffersSliceIoSlicesMutIter::new(&mut slices)
                .ct_eq_with_iter(SingletonIoSlice::new(&diff))
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - different lengths
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        assert_eq!(
            BuffersSliceIoSlicesMutIter::new(&mut slices)
                .ct_eq_with_iter(SingletonIoSlice::new(&src1))
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - vs empty
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        assert_eq!(
            BuffersSliceIoSlicesMutIter::new(&mut slices)
                .ct_eq_with_iter(EmptyIoSlices::default())
                .unwrap()
                .unwrap(),
            0
        );
    }
    {
        // ct_eq_with_iter - empty vs this
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        assert_eq!(
            EmptyIoSlices::default()
                .ct_eq_with_iter(BuffersSliceIoSlicesMutIter::new(&mut slices))
                .unwrap()
                .unwrap(),
            0
        );
    }
}
