use cocoon_tpm_utils_common::io_slices::*;
use core::convert;

#[test]
fn empty_io_slices() {
    {
        // next_slice_mut
        assert_eq!(EmptyIoSlices::default().next_slice_mut(None).unwrap(), None);
        assert_eq!(EmptyIoSlices::default().next_slice_mut(Some(1)).unwrap(), None);
    }
    {
        // copy_from_iter
        let src = [1u8, 2, 3];
        let copied = EmptyIoSlices::default()
            .copy_from_iter(&mut SingletonIoSlice::new(&src))
            .unwrap();
        assert_eq!(copied, 0);
    }
    {
        // copy_from_iter from empty source
        let copied = EmptyIoSlices::default()
            .copy_from_iter(&mut EmptyIoSlices::default())
            .unwrap();
        assert_eq!(copied, 0);
    }
    {
        // copy_from_iter_exhaustive (both empty — should succeed)
        EmptyIoSlices::default()
            .copy_from_iter_exhaustive(EmptyIoSlices::default())
            .unwrap();
    }
    {
        // copy_from_iter_exhaustive (non-empty source — should fail)
        let src = [1u8, 2, 3];
        assert!(
            EmptyIoSlices::default()
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
                .is_err()
        );
    }
}

#[test]
fn singleton_io_slice_mut() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_slice_mut
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let slice = iter.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(slice, &src);
        slice[0] = 99;
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 99);
    }
    {
        // next_slice_mut with max_len
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let slice = iter.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(slice, &src[..2]);
        slice[0] = 99;
        let slice = iter.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(slice, &src[2..]);
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 99);
    }
    {
        // copy_from_iter
        let mut buf = [0u8, 1, 2, 3, 4];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, src.len());
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter partial (source shorter)
        let mut buf = [0u8, 1, 2, 3, 4];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src[..3])).unwrap();
        assert_eq!(copied, 3);
        assert_eq!(&buf[..3], &src[..3]);
        assert_eq!(&buf[3..], &[3, 4]);
    }
    {
        // copy_from_iter partial (dest shorter)
        let mut buf = [0u8, 1, 2];
        let mut iter = SingletonIoSliceMut::new(&mut buf);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, 3);
        assert_eq!(buf, src[..3]);
    }
    {
        // copy_from_iter_exhaustive
        let mut buf = [0u8, 1, 2, 3, 4];
        SingletonIoSliceMut::new(&mut buf)
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
            .unwrap();
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut buf = [0u8, 1, 2];
        assert!(
            SingletonIoSliceMut::new(&mut buf)
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
                .is_err()
        );
    }
}

/// Helper to test IoSlicesMutIter on GenericIoSlicesMutIter,
/// with and without a head slice.
fn test_generic_io_slices_mut_iter_variant(with_head: bool) {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5];
    let head_buf = [98u8, 99];
    let expected_data_with_head = [98u8, 99, 1, 2, 3, 4, 5];
    let expected_data_without_head = [1u8, 2, 3, 4, 5];

    let head_src = if with_head { Some(head_buf) } else { None };
    let expected_slices: &[&[u8]] = if with_head {
        &[head_buf.as_ref(), src1.as_ref(), src2.as_ref()]
    } else {
        &[src1.as_ref(), src2.as_ref()]
    };
    let expected_data: &[u8] = if with_head {
        &expected_data_with_head
    } else {
        &expected_data_without_head
    };

    fn ok_mut(s: &mut [u8]) -> Result<&mut [u8], convert::Infallible> {
        Ok(s)
    }

    fn head_mut(h: &mut Option<[u8; 2]>) -> Option<&mut [u8]> {
        h.as_mut().map(|h| h.as_mut_slice())
    }

    let total_len = expected_data.len();
    let first = expected_slices[0];

    {
        // next_slice_mut (write path): modify each slice and verify
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        for expected in expected_slices {
            let s = iter.next_slice_mut(None).unwrap().unwrap();
            assert_eq!(s, *expected);
            s[0] = 0xFF;
        }
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        drop(iter);
        if let Some(h) = &h {
            assert_eq!(h[0], 0xFF);
        }
        assert_eq!(b1[0], 0xFF);
        assert_eq!(b2[0], 0xFF);
    }
    {
        // next_slice_mut with max_len
        let mut b1 = src1;
        let mut b2 = src2;
        let mut h = head_src;
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        let s = iter.next_slice_mut(Some(1)).unwrap().unwrap();
        assert_eq!(s, &first[..1]);
        s[0] = 0xAA;
        let s = iter.next_slice_mut(Some(first.len())).unwrap().unwrap();
        assert_eq!(s, &first[1..]);
        drop(iter);
        if let Some(h) = &h {
            assert_eq!(h[0], 0xAA);
        } else {
            assert_eq!(b1[0], 0xAA);
        }
    }
    {
        // copy_from_iter (full)
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut h: Option<[u8; 2]> = head_src.map(|_| [0u8; 2]);
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(expected_data)).unwrap();
        assert_eq!(copied, total_len);
        drop(iter);
        if let Some(h) = &h {
            assert_eq!(h.as_slice(), &head_buf);
        }
        assert_eq!(&b1, &src1);
        assert_eq!(&b2, &src2);
    }
    {
        // copy_from_iter (source shorter)
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut h: Option<[u8; 2]> = head_src.map(|_| [0u8; 2]);
        let mut iter = GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        );
        let short = &expected_data[..2];
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(short)).unwrap();
        assert_eq!(copied, 2);
    }
    {
        // copy_from_iter (dest shorter): only head + buf1, no buf2
        let mut b1 = [0u8; 2];
        let mut h: Option<[u8; 2]> = head_src.map(|_| [0u8; 2]);
        let dest_len = src1.len() + if with_head { head_buf.len() } else { 0 };
        let mut iter = GenericIoSlicesMutIter::new([ok_mut(b1.as_mut_slice())].into_iter(), head_mut(&mut h));
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(expected_data)).unwrap();
        assert_eq!(copied, dest_len);
        drop(iter);
        if let Some(h) = &h {
            assert_eq!(h.as_slice(), &head_buf);
        }
        assert_eq!(&b1, &src1);
    }
    {
        // copy_from_iter_exhaustive
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut h: Option<[u8; 2]> = head_src.map(|_| [0u8; 2]);
        let head_len = if with_head { head_buf.len() } else { 0 };
        GenericIoSlicesMutIter::new(
            [ok_mut(b1.as_mut_slice()), ok_mut(b2.as_mut_slice())].into_iter(),
            head_mut(&mut h),
        )
        .copy_from_iter_exhaustive(SingletonIoSlice::new(expected_data))
        .unwrap();
        if let Some(h) = &h {
            assert_eq!(h.as_slice(), &expected_data[..head_len]);
        }
        assert_eq!(&b1, &expected_data[head_len..head_len + src1.len()]);
        assert_eq!(&b2, &expected_data[head_len + src1.len()..]);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut b1 = [0u8; 2];
        let mut h: Option<[u8; 2]> = head_src.map(|_| [0u8; 2]);
        assert!(
            GenericIoSlicesMutIter::new([ok_mut(b1.as_mut_slice())].into_iter(), head_mut(&mut h),)
                .copy_from_iter_exhaustive(SingletonIoSlice::new(expected_data))
                .is_err()
        );
    }
}

#[test]
fn generic_io_slices_mut_iter() {
    // without head
    test_generic_io_slices_mut_iter_variant(false);

    // with head
    test_generic_io_slices_mut_iter_variant(true);
}

#[test]
fn buffers_slice_io_slices_mut_iter() {
    let src1 = [1u8, 2];
    let src2 = [3u8, 4, 5];
    let combined = [1u8, 2, 3, 4, 5];
    let total_len = combined.len();
    {
        // next_slice_mut (write path)
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let s = iter.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xFF;
        let s = iter.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2);
        s[0] = 0xEE;
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        drop(iter);
        assert_eq!(b1[0], 0xFF);
        assert_eq!(b2[0], 0xEE);
    }
    {
        // next_slice_mut with max_len
        let mut b1 = src1;
        let mut slices = [b1.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let s = iter.next_slice_mut(Some(1)).unwrap().unwrap();
        assert_eq!(s, &src1[..1]);
        s[0] = 0xAA;
        let s = iter.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src1[1..]);
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        drop(iter);
        assert_eq!(b1[0], 0xAA);
    }
    {
        // copy_from_iter (full)
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&combined)).unwrap();
        assert_eq!(copied, total_len);
        drop(iter);
        assert_eq!(b1, [1, 2]);
        assert_eq!(b2, [3, 4, 5]);
    }
    {
        // copy_from_iter (source shorter)
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&combined[..2])).unwrap();
        assert_eq!(copied, 2);
        drop(iter);
        assert_eq!(b1, [1, 2]);
    }
    {
        // copy_from_iter (dest shorter)
        let mut b1 = [0u8; 2];
        let mut slices = [b1.as_mut_slice()];
        let mut iter = BuffersSliceIoSlicesMutIter::new(&mut slices);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&combined)).unwrap();
        assert_eq!(copied, 2);
        drop(iter);
        assert_eq!(b1, [1, 2]);
    }
    {
        // copy_from_iter_exhaustive
        let mut b1 = [0u8; 2];
        let mut b2 = [0u8; 3];
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        BuffersSliceIoSlicesMutIter::new(&mut slices)
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&combined))
            .unwrap();
        assert_eq!(b1, combined[..src1.len()]);
        assert_eq!(b2, combined[src1.len()..]);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut b1 = [0u8; 2];
        let mut slices = [b1.as_mut_slice()];
        assert!(
            BuffersSliceIoSlicesMutIter::new(&mut slices)
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&combined))
                .is_err()
        );
    }
}

#[test]
fn covariant_io_slices_iter_ref() {
    let src = [1u8, 2, 3, 4, 5];
    {
        // next_slice_mut
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src);
        s[0] = 0xFF;
        assert_eq!(covariant.next_slice_mut(None).unwrap(), None);
        drop(covariant);
        assert_eq!(buf[0], 0xFF);
    }
    {
        // next_slice_mut with max_len
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let s = covariant.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        s[0] = 0xAA;
        let s = covariant.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[2..]);
        assert_eq!(covariant.next_slice_mut(None).unwrap(), None);
        drop(covariant);
        assert_eq!(buf[0], 0xAA);
    }
    {
        // advancing covariant ref advances the original
        let mut buf = src;
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        {
            let mut covariant = inner.as_ref();
            let s = covariant.next_slice_mut(Some(3)).unwrap().unwrap();
            assert_eq!(s, &src[..3]);
            s[0] = 0xBB;
        }
        // inner should now be advanced past the first 3 bytes
        let s = inner.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[3..]);
        assert_eq!(inner.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xBB);
    }
    {
        // next_slice_mut on empty
        let mut buf = [0u8; 0];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        assert_eq!(covariant.next_slice_mut(None).unwrap(), None);
    }
    {
        // copy_from_iter
        let mut buf = [0u8; 5];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let copied = covariant.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, src.len());
        drop(covariant);
        drop(inner);
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter partial (source shorter)
        let mut buf = [0u8; 5];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let copied = covariant.copy_from_iter(&mut SingletonIoSlice::new(&src[..3])).unwrap();
        assert_eq!(copied, 3);
        drop(covariant);
        drop(inner);
        assert_eq!(&buf[..3], &src[..3]);
    }
    {
        // copy_from_iter partial (dest shorter)
        let mut buf = [0u8; 3];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        let mut covariant = inner.as_ref();
        let copied = covariant.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, 3);
        drop(covariant);
        drop(inner);
        assert_eq!(buf, src[..3]);
    }
    {
        // copy_from_iter_exhaustive
        let mut buf = [0u8; 5];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        inner
            .as_ref()
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
            .unwrap();
        drop(inner);
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut buf = [0u8; 3];
        let mut inner = SingletonIoSliceMut::new(&mut buf);
        assert!(
            inner
                .as_ref()
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
                .is_err()
        );
    }
}

#[test]
fn io_slices_iter_map_err() {
    let src = [1u8, 2, 3, 4, 5];
    let map_fn = |e: convert::Infallible| -> convert::Infallible { match e {} };
    {
        // next_slice_mut
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let s = iter.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src);
        s[0] = 0xFF;
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xFF);
    }
    {
        // next_slice_mut with max_len
        let mut buf = src;
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let s = iter.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src[..2]);
        s[0] = 0xAA;
        let s = iter.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[2..]);
        assert_eq!(iter.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xAA);
    }
    {
        // copy_from_iter
        let mut buf = [0u8; 5];
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, src.len());
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter partial (source shorter)
        let mut buf = [0u8; 5];
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src[..3])).unwrap();
        assert_eq!(copied, 3);
        assert_eq!(&buf[..3], &src[..3]);
    }
    {
        // copy_from_iter partial (dest shorter)
        let mut buf = [0u8; 3];
        let mut iter = SingletonIoSliceMut::new(&mut buf).map_err(map_fn);
        let copied = iter.copy_from_iter(&mut SingletonIoSlice::new(&src)).unwrap();
        assert_eq!(copied, 3);
        assert_eq!(buf, src[..3]);
    }
    {
        // copy_from_iter_exhaustive
        let mut buf = [0u8; 5];
        SingletonIoSliceMut::new(&mut buf)
            .map_err(map_fn)
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
            .unwrap();
        assert_eq!(buf, src);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut buf = [0u8; 3];
        assert!(
            SingletonIoSliceMut::new(&mut buf)
                .map_err(map_fn)
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&src))
                .is_err()
        );
    }
}

#[test]
fn io_slices_iter_take_exact() {
    let src = [1u8, 2, 3, 4, 5, 6, 7, 8];
    {
        // next_slice_mut
        let mut buf = src;
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(5);
        let s = take.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[..5]);
        s[0] = 0xFF;
        assert_eq!(take.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xFF);
    }
    {
        // next_slice_mut with max_len smaller than remaining
        let mut buf = src;
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(5);
        let s = take.next_slice_mut(Some(3)).unwrap().unwrap();
        assert_eq!(s, &src[..3]);
        s[0] = 0xAA;
        let s = take.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src[3..5]);
        assert_eq!(take.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf[0], 0xAA);
    }
    {
        // next_slice_mut with max_len larger than remaining
        let mut buf = src;
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(5);
        let s = take.next_slice_mut(Some(100)).unwrap().unwrap();
        assert_eq!(s, &src[..5]);
        assert_eq!(take.next_slice_mut(None).unwrap(), None);
    }
    {
        // take_exact(0)
        let mut buf = src;
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(0);
        assert_eq!(take.next_slice_mut(None).unwrap(), None);
    }
    {
        // take_exact larger than underlying iterator errors
        let mut buf = src;
        let short_len = 3;
        let mut take = SingletonIoSliceMut::new(&mut buf[..short_len]).take_exact(5);
        let s = take.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src[..short_len]);
        assert!(take.next_slice_mut(None).is_err());
    }
    {
        // take_exact over multiple buffers
        let src1 = [1u8, 2];
        let src2 = [3u8, 4, 5, 6, 7];
        let mut b1 = src1;
        let mut b2 = src2;
        let mut slices = [b1.as_mut_slice(), b2.as_mut_slice()];
        let mut take = BuffersSliceIoSlicesMutIter::new(&mut slices).take_exact(4);
        let s = take.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xFF;
        let s = take.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2[..2]);
        assert_eq!(take.next_slice_mut(None).unwrap(), None);
        drop(take);
        assert_eq!(b1[0], 0xFF);
    }
    {
        // copy_from_iter
        let mut buf = [0u8; 8];
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(5);
        let copied = take
            .copy_from_iter(&mut SingletonIoSlice::new(&src[..5]).take_exact(5))
            .unwrap();
        assert_eq!(copied, 5);
        drop(take);
        assert_eq!(&buf[..5], &src[..5]);
    }
    {
        // copy_from_iter partial (source shorter)
        let mut buf = [0u8; 8];
        let mut take = SingletonIoSliceMut::new(&mut buf).take_exact(5);
        let copied = take
            .copy_from_iter(&mut SingletonIoSlice::new(&src[..2]).take_exact(2))
            .unwrap();
        assert_eq!(copied, 2);
        drop(take);
        assert_eq!(&buf[..2], &src[..2]);
    }
    {
        // copy_from_iter_exhaustive
        let mut buf = [0u8; 8];
        SingletonIoSliceMut::new(&mut buf)
            .take_exact(5)
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&src[..5]).take_exact(5))
            .unwrap();
        assert_eq!(&buf[..5], &src[..5]);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut buf = [0u8; 8];
        assert!(
            SingletonIoSliceMut::new(&mut buf)
                .take_exact(5)
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&src).take_exact(8))
                .is_err()
        );
    }
}

#[test]
fn io_slices_iter_chain() {
    let src1 = [1u8, 2, 3];
    let src2 = [4u8, 5, 6, 7, 8];
    let combined = [1u8, 2, 3, 4, 5, 6, 7, 8];
    {
        // next_slice_mut
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xFF;
        let s = chain.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2);
        s[0] = 0xEE;
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xFF);
        assert_eq!(buf2[0], 0xEE);
    }
    {
        // next_slice_mut with max_len within first iterator
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_slice_mut(Some(2)).unwrap().unwrap();
        assert_eq!(s, &src1[..2]);
        s[0] = 0xAA;
        let s = chain.next_slice_mut(Some(10)).unwrap().unwrap();
        assert_eq!(s, &src1[2..]);
        let s = chain.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src2);
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xAA);
    }
    {
        // next_slice_mut with max_len spanning across iterators
        let mut buf1 = src1;
        let mut buf2 = src2;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let s = chain.next_slice_mut(Some(5)).unwrap().unwrap();
        assert_eq!(s, &src1);
        let s = chain.next_slice_mut(Some(5)).unwrap().unwrap();
        assert_eq!(s, &src2);
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
    }
    {
        // chain with empty first
        let mut buf1 = src1;
        let mut chain = EmptyIoSlices::default().chain(SingletonIoSliceMut::new(&mut buf1));
        let s = chain.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        s[0] = 0xBB;
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
        assert_eq!(buf1[0], 0xBB);
    }
    {
        // chain with empty second
        let mut buf1 = src1;
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(EmptyIoSlices::default());
        let s = chain.next_slice_mut(None).unwrap().unwrap();
        assert_eq!(s, &src1);
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
    }
    {
        // chain of two empties
        let mut chain = EmptyIoSlices::default().chain(EmptyIoSlices::default());
        assert_eq!(chain.next_slice_mut(None).unwrap(), None);
    }
    {
        // copy_from_iter
        let mut buf1 = [0u8; 3];
        let mut buf2 = [0u8; 5];
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let copied = chain.copy_from_iter(&mut SingletonIoSlice::new(&combined)).unwrap();
        assert_eq!(copied, combined.len());
        assert_eq!(buf1, combined[..src1.len()]);
        assert_eq!(buf2, combined[src1.len()..]);
    }
    {
        // copy_from_iter partial (source shorter)
        let mut buf1 = [0u8; 3];
        let mut buf2 = [0u8; 5];
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(SingletonIoSliceMut::new(&mut buf2));
        let copied = chain
            .copy_from_iter(&mut SingletonIoSlice::new(&combined[..2]))
            .unwrap();
        assert_eq!(copied, 2);
        assert_eq!(&buf1[..2], &combined[..2]);
    }
    {
        // copy_from_iter partial (dest shorter)
        let mut buf1 = [0u8; 3];
        let mut chain = SingletonIoSliceMut::new(&mut buf1).chain(EmptyIoSlices::default());
        let copied = chain.copy_from_iter(&mut SingletonIoSlice::new(&combined)).unwrap();
        assert_eq!(copied, src1.len());
        assert_eq!(buf1, combined[..src1.len()]);
    }
    {
        // copy_from_iter_exhaustive
        let mut buf1 = [0u8; 3];
        let mut buf2 = [0u8; 5];
        SingletonIoSliceMut::new(&mut buf1)
            .chain(SingletonIoSliceMut::new(&mut buf2))
            .copy_from_iter_exhaustive(SingletonIoSlice::new(&combined))
            .unwrap();
        assert_eq!(buf1, combined[..src1.len()]);
        assert_eq!(buf2, combined[src1.len()..]);
    }
    {
        // copy_from_iter_exhaustive length mismatch
        let mut buf1 = [0u8; 3];
        assert!(
            SingletonIoSliceMut::new(&mut buf1)
                .chain(EmptyIoSlices::default())
                .copy_from_iter_exhaustive(SingletonIoSlice::new(&combined))
                .is_err()
        );
    }
}
