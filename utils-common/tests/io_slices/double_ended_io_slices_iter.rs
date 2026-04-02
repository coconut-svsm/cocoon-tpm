use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn singleton_io_slice() {
    let buf = [1u8, 2, 3, 4, 5];
    {
        // next_back_slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len smaller than slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_back_slice(Some(3)).unwrap().unwrap(), &buf[2..]);
        assert_eq!(iter.next_back_slice(Some(10)).unwrap().unwrap(), &buf[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len larger than slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &buf);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice on empty slice
        let mut iter = SingletonIoSlice::new(&[]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut iter = SingletonIoSlice::new(&buf);
        assert_eq!(iter.next_slice(Some(2)).unwrap().unwrap(), &buf[..2]);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &buf[3..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf[2..3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip_back(buf.len()).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip_back(2).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf[..3]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        assert!(matches!(
            SingletonIoSlice::new(&buf).skip_back(buf.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut iter = SingletonIoSlice::new(&buf);
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn singleton_io_slice_mut() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_back_slice (read path)
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len smaller than slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_back_slice(Some(3)).unwrap().unwrap(), &src[2..]);
        assert_eq!(iter.next_back_slice(Some(10)).unwrap().unwrap(), &src[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len larger than slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &src);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice on empty
        let mut buf = [0u8; 0];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_slice(Some(2)).unwrap().unwrap(), &src[..2]);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &src[3..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src[2..3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip_back(src.len()).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip_back(2).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src[..3]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut buf = src;
        assert!(matches!(
            SingletonIoSliceMut::new(&mut buf).skip_back(src.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn buffers_slice_io_slices_iter() {
    let buf1 = [1u8, 2];
    let buf2 = [3u8, 4, 5, 6, 7];
    let slices = [buf1.as_slice(), buf2.as_slice()];
    {
        // next_back_slice
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len smaller than last buffer
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_back_slice(Some(3)).unwrap().unwrap(), &buf2[2..]);
        assert_eq!(iter.next_back_slice(Some(10)).unwrap().unwrap(), &buf2[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len larger than buffers
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len spanning across buffers
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_back_slice(Some(4)).unwrap().unwrap(), &buf2[1..]);
        assert_eq!(iter.next_back_slice(Some(4)).unwrap().unwrap(), &buf2[..1]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice on empty slices
        let empty: [&[u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesIter::new(&empty);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let slices_with_empty = [buf1.as_slice(), &[], buf2.as_slice()];
        let mut iter = BuffersSliceIoSlicesIter::new(&slices_with_empty);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &buf1[..1]);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &buf2[3..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2[..3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        iter.skip_back(buf1.len() + buf2.len()).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle of last buffer
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        iter.skip_back(3).unwrap();
        // remaining: buf1 + buf2[..2]
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back across buffer boundary
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        iter.skip_back(buf2.len() + 1).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1[..1]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        assert!(matches!(
            iter.skip_back(buf1.len() + buf2.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut iter = BuffersSliceIoSlicesIter::new(&slices);
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5, 6, 7];
    {
        // next_back_slice
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len smaller than last buffer
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice(Some(3)).unwrap().unwrap(), &src2[2..]);
        assert_eq!(iter.next_back_slice(Some(10)).unwrap().unwrap(), &src2[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len larger than buffers
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_back_slice(Some(100)).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice on empty
        let mut slices: [&mut [u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let mut b1 = src1;
        let mut empty = [0u8; 0];
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), empty.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &src1[..1]);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &src2[3..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &src1[1..]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src2[..3]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        iter.skip_back(src1.len() + src2.len()).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle of last buffer
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        iter.skip_back(3).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src2[..2]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back across buffer boundary
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        iter.skip_back(src2.len() + 1).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1[..1]);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert!(matches!(
            iter.skip_back(src1.len() + src2.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn empty_io_slices() {
    {
        // next_back_slice
        assert_eq!(EmptyIoSlices::default().next_back_slice(None).unwrap(), None);
        assert_eq!(EmptyIoSlices::default().next_back_slice(Some(1)).unwrap(), None);
    }
    {
        // skip_back(0)
        let mut iter = EmptyIoSlices::default();
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        assert!(matches!(
            EmptyIoSlices::default().skip_back(1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
}

#[test]
fn io_slices_iter_map_err() {
    let buf1 = [1u8, 2];
    let buf2 = [3u8, 4, 5];
    let slices = [buf1.as_slice(), buf2.as_slice()];
    let total_len = buf1.len() + buf2.len();
    let map_fn = |e: convert::Infallible| -> convert::Infallible { match e {} };
    {
        // next_back_slice passes through
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &buf2[1..]);
        assert_eq!(iter.next_back_slice(Some(10)).unwrap().unwrap(), &buf2[..1]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert_eq!(iter.next_slice(Some(1)).unwrap().unwrap(), &buf1[..1]);
        assert_eq!(iter.next_back_slice(Some(2)).unwrap().unwrap(), &buf2[1..]);
        assert_eq!(iter.next_slice(None).unwrap().unwrap(), &buf1[1..]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2[..1]);
        assert_eq!(iter.next_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        iter.skip_back(total_len).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        iter.skip_back(2).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2[..1]);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        assert!(matches!(
            iter.skip_back(total_len + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut iter = BuffersSliceIoSlicesIter::new(&slices).map_err(map_fn);
        iter.skip_back(0).unwrap();
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(iter.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(iter.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn covariant_io_slices_iter_ref() {
    let buf = [1u8, 2, 3, 4, 5];
    {
        // next_back_slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_back_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len smaller than slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_back_slice(Some(3)).unwrap().unwrap(), &buf[2..]);
        assert_eq!(covariant.next_back_slice(Some(10)).unwrap().unwrap(), &buf[..2]);
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len larger than slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_back_slice(Some(100)).unwrap().unwrap(), &buf);
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // advancing covariant ref advances the original (from back)
        let mut inner = SingletonIoSlice::new(&buf);
        {
            let mut covariant = inner.as_ref();
            assert_eq!(covariant.next_back_slice(Some(2)).unwrap().unwrap(), &buf[3..]);
        }
        // inner should now have the last 2 bytes consumed
        assert_eq!(inner.next_back_slice(None).unwrap().unwrap(), &buf[..3]);
        assert_eq!(inner.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice on empty
        let mut inner = SingletonIoSlice::new(&[]);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice(Some(2)).unwrap().unwrap(), &buf[..2]);
        assert_eq!(covariant.next_back_slice(Some(2)).unwrap().unwrap(), &buf[3..]);
        assert_eq!(covariant.next_slice(None).unwrap().unwrap(), &buf[2..3]);
        assert_eq!(covariant.next_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip_back(buf.len()).unwrap();
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back to middle
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip_back(2).unwrap();
        assert_eq!(covariant.next_back_slice(None).unwrap().unwrap(), &buf[..3]);
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        assert!(matches!(
            covariant.skip_back(buf.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut inner = SingletonIoSlice::new(&buf);
        let mut covariant = inner.as_ref();
        covariant.skip_back(0).unwrap();
        assert_eq!(covariant.next_back_slice(None).unwrap().unwrap(), &buf);
        assert_eq!(covariant.next_back_slice(None).unwrap(), None);
    }
}

#[test]
fn io_slices_iter_chain() {
    let buf1 = [1u8, 2, 3];
    let buf2 = [4u8, 5, 6, 7, 8];
    {
        // next_back_slice
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len within second iterator
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_back_slice(Some(3)).unwrap().unwrap(), &buf2[2..]);
        assert_eq!(chain.next_back_slice(Some(10)).unwrap().unwrap(), &buf2[..2]);
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // next_back_slice with max_len spanning across iterators
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_back_slice(Some(7)).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_back_slice(Some(7)).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // chain with empty first
        let mut chain = EmptyIoSlices::default().chain(SingletonIoSlice::new(&buf1));
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // chain with empty second
        let mut chain = SingletonIoSlice::new(&buf1).chain(EmptyIoSlices::default());
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // chain of two empties
        let mut chain = EmptyIoSlices::default().chain(EmptyIoSlices::default());
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // interleave next_slice and next_back_slice
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert_eq!(chain.next_slice(Some(2)).unwrap().unwrap(), &buf1[..2]);
        assert_eq!(chain.next_back_slice(Some(2)).unwrap().unwrap(), &buf2[3..]);
        assert_eq!(chain.next_slice(None).unwrap().unwrap(), &buf1[2..]);
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf2[..3]);
        assert_eq!(chain.next_slice(None).unwrap(), None);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back all
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip_back(buf1.len() + buf2.len()).unwrap();
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back within second iterator
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip_back(2).unwrap();
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf2[..3]);
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back across iterator boundary
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip_back(buf2.len() + 1).unwrap();
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1[..2]);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
    {
        // skip_back past beginning
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        assert!(matches!(
            chain.skip_back(buf1.len() + buf2.len() + 1),
            Err(IoSlicesIterError::IoSlicesError(IoSlicesError::BuffersExhausted))
        ));
    }
    {
        // skip_back(0)
        let mut chain = SingletonIoSlice::new(&buf1).chain(SingletonIoSlice::new(&buf2));
        chain.skip_back(0).unwrap();
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf2);
        assert_eq!(chain.next_back_slice(None).unwrap().unwrap(), &buf1);
        assert_eq!(chain.next_back_slice(None).unwrap(), None);
    }
}
