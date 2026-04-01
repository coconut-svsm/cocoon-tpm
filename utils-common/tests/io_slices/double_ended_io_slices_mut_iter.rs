use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn empty_io_slices() {
    {
        // next_back_slice_mut
        assert_eq!(EmptyIoSlices::default().next_back_slice_mut(None).unwrap(), None);
        assert_eq!(EmptyIoSlices::default().next_back_slice_mut(Some(1)).unwrap(), None);
    }
}

#[test]
fn singleton_io_slice_mut() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_back_slice_mut
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let s = iter.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src);
        s[4] = 0xFF;
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf[4], 0xFF);
    }
    {
        // next_back_slice_mut with max_len smaller than slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let s = iter.next_back_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src[2..]);
        s[0] = 0xAA;
        let s = iter.next_back_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf[2], 0xAA);
    }
    {
        // next_back_slice_mut with max_len larger than slice
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let s = iter.next_back_slice_mut(Some(100)).unwrap().unwrap();
        assert_eq!(s, &src);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // next_back_slice_mut on empty
        let mut buf = [0u8; 0];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // interleave next_slice_mut and next_back_slice_mut
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let s = iter.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        s[0] = 0xBB;
        let s = iter.next_back_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[3..]);
        s[1] = 0xCC;
        let s = iter.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[2..3]);
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xBB);
        assert_eq!(buf[4], 0xCC);
    }
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5, 6, 7];
    {
        // next_back_slice_mut
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let s = iter.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2);
        s[0] = 0xFF;
        let s = iter.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xEE;
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        drop(iter);
        assert_eq!(b1[0], 0xEE);
        assert_eq!(b2[0], 0xFF);
    }
    {
        // next_back_slice_mut with max_len smaller than last buffer
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let s = iter.next_back_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src2[2..]);
        s[0] = 0xAA;
        let s = iter.next_back_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src2[..2]);
        let s = iter.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        drop(iter);
        assert_eq!(b2[2], 0xAA);
    }
    {
        // next_back_slice_mut on empty
        let mut slices: [&mut [u8]; 0] = [];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // empty buffers are skipped
        let mut b1 = src1;
        let mut empty = [0u8; 0];
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), empty.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        assert_eq!(iter.next_back_slice_mut(None).unwrap().unwrap(), &src2);
        assert_eq!(iter.next_back_slice_mut(None).unwrap().unwrap(), &src1);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // interleave next_slice_mut and next_back_slice_mut
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let s = iter.next_slice_mut(Some(1)).unwrap().unwrap();
        assert_eq!(s, &src1[..1]);
        s[0] = 0xBB;
        let s = iter.next_back_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src2[3..]);
        s[1] = 0xCC;
        assert_eq!(iter.next_slice_mut(None).unwrap().unwrap(), &src1[1..]);
        assert_eq!(iter.next_back_slice_mut(None).unwrap().unwrap(), &src2[..3]);
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        drop(iter);
        assert_eq!(b1[0], 0xBB);
        assert_eq!(b2[4], 0xCC);
    }
}

#[test]
fn covariant_io_slices_iter_ref() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_back_slice_mut
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src);
        s[4] = 0xFF;
        assert_eq!(covariant.next_back_slice_mut(None).unwrap(), None);
        drop(covariant);
        assert_eq!(buf[4], 0xFF);
    }
    {
        // next_back_slice_mut with max_len smaller than slice
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_back_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src[2..]);
        s[0] = 0xAA;
        let s = covariant.next_back_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        assert_eq!(covariant.next_back_slice_mut(None).unwrap(), None);
        drop(covariant);
        assert_eq!(buf[2], 0xAA);
    }
    {
        // next_back_slice_mut with max_len larger than slice
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_back_slice_mut(Some(100)).unwrap().unwrap();
        assert_eq!(s, &src);
        assert_eq!(covariant.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // advancing covariant ref advances the original (from back)
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        {
            let mut covariant = inner.as_ref();
            let s = covariant.next_back_slice_mut(Some(2)).unwrap().unwrap();
            assert_eq!(s, &src[3..]);
            s[0] = 0xBB;
        }
        // inner should now have the last 2 bytes consumed
        let s = inner.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[..3]);
        assert_eq!(inner.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf[3], 0xBB);
    }
    {
        // next_back_slice_mut on empty
        let mut buf = [0u8; 0];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // interleave next_slice_mut and next_back_slice_mut
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        s[0] = 0xDD;
        let s = covariant.next_back_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[3..]);
        s[1] = 0xEE;
        let s = covariant.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[2..3]);
        assert_eq!(covariant.next_slice_mut(None).unwrap(), None);
        drop(covariant);
        assert_eq!(buf[0], 0xDD);
        assert_eq!(buf[4], 0xEE);
    }
}

#[test]
fn io_slices_iter_map_err() {
    let src = [1u8, 2, 3, 4, 5];
    let map_fn = |e: convert::Infallible| -> convert::Infallible { match e {} };
    {
        // next_back_slice_mut
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let s = iter.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src);
        s[4] = 0xFF;
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf[4], 0xFF);
    }
    {
        // next_back_slice_mut with max_len
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let s = iter.next_back_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src[2..]);
        s[0] = 0xAA;
        let s = iter.next_back_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        assert_eq!(iter.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf[2], 0xAA);
    }
}

#[test]
fn io_slices_iter_chain() {
    let src1 = [1u8, 2, 3];
    let src2 = [4u8, 5, 6, 7, 8];
    {
        // next_back_slice_mut
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2);
        s[0] = 0xFF;
        let s = chain.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xEE;
        assert_eq!(chain.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xEE);
        assert_eq!(buf2[0], 0xFF);
    }
    {
        // next_back_slice_mut with max_len within second iterator
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_back_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src2[2..]);
        s[0] = 0xAA;
        let s = chain.next_back_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src2[..2]);
        let s = chain.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        assert_eq!(chain.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf2[2], 0xAA);
    }
    {
        // chain with empty first
        let mut buf1 = src1;
        let mut chain = EmptyIoSlices::default().chain(SingletonIoSliceMut::new(&mut buf1));
        let s = chain.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xBB;
        assert_eq!(chain.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xBB);
    }
    {
        // chain with empty second
        let mut buf1 = src1;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(EmptyIoSlices::default());
        let s = chain.next_back_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xBB;
        assert_eq!(chain.next_back_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xBB);
    }
    {
        // chain of two empties
        let mut chain = EmptyIoSlices::default().chain(EmptyIoSlices::default());
        assert_eq!(chain.next_back_slice_mut(None).unwrap(), None);
    }
    {
        // interleave next_slice_mut and next_back_slice_mut
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src1[..2]);
        s[0] = 0xDD;
        let s = chain.next_back_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src2[3..]);
        s[1] = 0xEE;
        assert_eq!(chain.next_slice_mut(None).unwrap().unwrap(), &src1[2..]);
        assert_eq!(chain.next_back_slice_mut(None).unwrap().unwrap(), &src2[..3]);
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xDD);
        assert_eq!(buf2[4], 0xEE);
    }
}
