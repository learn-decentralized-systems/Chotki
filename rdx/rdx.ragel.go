package rdx

import "fmt"

var __RDX_actions = []int8{0, 1, 0, 1, 1, 1, 2, 1, 3, 1, 4, 1, 5, 1, 6, 1, 7, 1, 8, 1, 9, 1, 10, 2, 1, 5, 2, 1, 7, 2, 1, 9, 2, 1, 10, 2, 2, 5, 2, 2, 7, 2, 2, 9, 2, 2, 10, 2, 3, 5, 2, 3, 7, 2, 3, 9, 2, 3, 10, 2, 4, 5, 2, 4, 7, 2, 4, 9, 2, 4, 10, 2, 6, 0, 2, 6, 5, 2, 6, 7, 2, 6, 9, 2, 6, 10, 2, 8, 0, 2, 8, 5, 2, 8, 7, 2, 8, 9, 2, 8, 10, 0}
var __RDX_key_offsets = []int16{0, 0, 23, 30, 32, 34, 38, 42, 44, 50, 56, 68, 75, 82, 90, 99, 105, 111, 117, 123, 146, 169, 178, 201, 215, 226, 249, 268, 284, 299, 322, 343, 359, 0}
var __RDX_trans_keys = []byte{32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 34, 46, 57, 92, 120, 48, 49, 48, 57, 48, 57, 69, 101, 48, 57, 43, 45, 48, 57, 48, 57, 48, 57, 65, 70, 97, 102, 48, 57, 65, 70, 97, 102, 45, 95, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 95, 48, 57, 65, 90, 97, 122, 45, 48, 57, 65, 70, 97, 102, 43, 45, 48, 57, 65, 70, 97, 102, 34, 47, 92, 98, 102, 110, 114, 116, 117, 48, 57, 65, 70, 97, 102, 48, 57, 65, 70, 97, 102, 48, 57, 65, 70, 97, 102, 48, 57, 65, 70, 97, 102, 32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 44, 58, 91, 93, 123, 125, 9, 13, 32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 44, 46, 58, 69, 91, 93, 101, 123, 125, 9, 13, 48, 57, 32, 44, 58, 91, 93, 123, 125, 9, 13, 48, 57, 32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 44, 45, 46, 58, 69, 91, 93, 101, 123, 125, 9, 13, 48, 57, 65, 70, 97, 102, 32, 44, 45, 58, 91, 93, 123, 125, 9, 13, 48, 57, 65, 70, 97, 102, 32, 44, 58, 91, 93, 123, 125, 9, 13, 48, 57, 65, 70, 97, 102, 32, 34, 44, 58, 91, 93, 95, 123, 125, 9, 13, 43, 45, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 44, 45, 58, 91, 93, 95, 123, 125, 9, 13, 48, 57, 65, 70, 71, 90, 97, 102, 103, 122, 32, 44, 58, 91, 93, 95, 123, 125, 9, 13, 48, 57, 65, 90, 97, 122, 32, 44, 45, 58, 91, 93, 123, 125, 9, 13, 48, 57, 65, 70, 97, 102, 0}
var __RDX_single_lengths = []int8{0, 9, 5, 0, 0, 2, 2, 0, 0, 0, 2, 1, 1, 2, 9, 0, 0, 0, 0, 9, 9, 7, 9, 10, 7, 9, 11, 8, 7, 9, 9, 8, 8, 0}
var __RDX_range_lengths = []int8{0, 7, 1, 1, 1, 1, 1, 1, 3, 3, 5, 3, 3, 3, 0, 3, 3, 3, 3, 7, 7, 1, 7, 2, 2, 7, 4, 4, 4, 7, 6, 4, 4, 0}
var __RDX_index_offsets = []int16{0, 0, 17, 24, 26, 28, 32, 36, 38, 42, 46, 54, 59, 64, 70, 80, 84, 88, 92, 96, 113, 130, 139, 156, 169, 179, 196, 212, 225, 237, 254, 270, 283, 0}
var __RDX_cond_targs = []int8{1, 2, 1, 1, 1, 19, 11, 1, 20, 1, 3, 26, 10, 11, 10, 11, 0, 21, 0, 0, 14, 0, 0, 2, 23, 0, 5, 0, 6, 6, 5, 0, 7, 7, 24, 0, 24, 0, 27, 27, 27, 0, 28, 28, 28, 0, 8, 31, 30, 30, 31, 30, 31, 0, 31, 31, 31, 31, 0, 8, 12, 12, 12, 0, 7, 8, 32, 12, 12, 0, 2, 2, 2, 2, 2, 2, 2, 2, 15, 0, 16, 16, 16, 0, 17, 17, 17, 0, 18, 18, 18, 0, 2, 2, 2, 0, 1, 2, 1, 1, 1, 19, 11, 1, 20, 1, 3, 26, 10, 11, 10, 11, 0, 1, 2, 1, 1, 1, 19, 11, 1, 20, 1, 3, 26, 10, 11, 10, 11, 0, 22, 22, 22, 22, 25, 22, 29, 22, 0, 22, 2, 22, 22, 22, 25, 11, 22, 29, 22, 3, 26, 10, 11, 10, 11, 0, 22, 22, 4, 22, 6, 22, 25, 6, 22, 29, 22, 23, 0, 22, 22, 22, 22, 25, 22, 29, 22, 24, 0, 22, 2, 22, 22, 22, 25, 11, 22, 29, 22, 3, 26, 10, 11, 10, 11, 0, 22, 22, 8, 4, 22, 13, 22, 25, 13, 22, 29, 22, 26, 12, 12, 0, 22, 22, 9, 22, 22, 25, 22, 29, 22, 27, 27, 27, 0, 22, 22, 22, 22, 25, 22, 29, 22, 28, 28, 28, 0, 22, 2, 22, 22, 22, 25, 11, 22, 29, 22, 3, 26, 10, 11, 10, 11, 0, 22, 22, 8, 22, 22, 25, 31, 22, 29, 22, 30, 30, 31, 30, 31, 0, 22, 22, 22, 22, 25, 31, 22, 29, 22, 31, 31, 31, 0, 22, 22, 8, 22, 22, 25, 22, 29, 22, 32, 12, 12, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 0}
var __RDX_cond_actions = []int8{0, 1, 19, 21, 15, 0, 1, 11, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 86, 95, 98, 92, 17, 86, 89, 17, 17, 86, 86, 86, 86, 86, 86, 0, 13, 71, 80, 83, 77, 13, 71, 74, 13, 13, 71, 71, 71, 71, 71, 71, 0, 7, 53, 56, 50, 7, 47, 7, 7, 0, 0, 1, 19, 21, 15, 0, 1, 11, 0, 0, 1, 1, 1, 1, 1, 1, 0, 3, 29, 0, 32, 0, 26, 3, 0, 23, 3, 3, 0, 0, 0, 19, 21, 15, 0, 11, 0, 0, 0, 0, 17, 86, 95, 98, 92, 17, 86, 89, 17, 17, 86, 86, 86, 86, 86, 86, 0, 3, 29, 0, 0, 32, 0, 26, 3, 0, 23, 3, 3, 0, 0, 0, 0, 5, 41, 0, 44, 38, 5, 35, 5, 5, 0, 0, 0, 0, 5, 41, 44, 38, 5, 35, 5, 5, 0, 0, 0, 0, 13, 71, 80, 83, 77, 13, 71, 74, 13, 13, 71, 71, 71, 71, 71, 71, 0, 9, 65, 0, 68, 62, 9, 0, 59, 9, 9, 0, 0, 0, 0, 0, 0, 9, 65, 68, 62, 9, 0, 59, 9, 9, 0, 0, 0, 0, 0, 19, 0, 21, 15, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 3, 0, 17, 3, 5, 5, 13, 9, 9, 0, 0}
var __RDX_eof_trans = []int16{297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 0}
var _RDX_start int = 1
var _ = _RDX_start
var _RDX_first_final int = 21
var _ = _RDX_first_final
var _RDX_error int = 0
var _ = _RDX_error
var _RDX_en_main int = 1
var _ = _RDX_en_main

func ParseRDX(data []byte) (rdx *RDX, err error) {

	var mark [RdxMaxNesting]int
	nest, cs, p, pe, eof := 0, 0, 0, len(data), len(data)

	rdx = &RDX{}

	{
		cs = int(_RDX_start)

	}
	{
		var _klen int
		var _trans uint = 0
		var _keys int
		var _acts int
		var _nacts uint
	_resume:
		{

		}
		if p == pe && p != eof {
			goto _out

		}
		if p == eof {
			if __RDX_eof_trans[cs] > 0 {
				_trans = uint(__RDX_eof_trans[cs]) - 1

			}

		} else {
			_keys = int(__RDX_key_offsets[cs])

			_trans = uint(__RDX_index_offsets[cs])
			_klen = int(__RDX_single_lengths[cs])
			if _klen > 0 {
				var _lower int = _keys
				var _upper int = _keys + _klen - 1
				var _mid int
				for {
					if _upper < _lower {
						_keys += _klen
						_trans += uint(_klen)
						break

					}
					_mid = _lower + ((_upper - _lower) >> 1)
					if (data[p]) < __RDX_trans_keys[_mid] {
						_upper = _mid - 1

					} else if (data[p]) > __RDX_trans_keys[_mid] {
						_lower = _mid + 1

					} else {
						_trans += uint((_mid - _keys))
						goto _match

					}

				}

			}
			_klen = int(__RDX_range_lengths[cs])
			if _klen > 0 {
				var _lower int = _keys
				var _upper int = _keys + (_klen << 1) - 2
				var _mid int
				for {
					if _upper < _lower {
						_trans += uint(_klen)
						break

					}
					_mid = _lower + (((_upper - _lower) >> 1) & ^1)
					if (data[p]) < __RDX_trans_keys[_mid] {
						_upper = _mid - 2

					} else if (data[p]) > __RDX_trans_keys[_mid+1] {
						_lower = _mid + 2

					} else {
						_trans += uint(((_mid - _keys) >> 1))
						break

					}

				}

			}
		_match:
			{

			}

		}
		cs = int(__RDX_cond_targs[_trans])
		if __RDX_cond_actions[_trans] != 0 {
			_acts = int(__RDX_cond_actions[_trans])

			_nacts = uint(__RDX_actions[_acts])
			_acts += 1
			for _nacts > 0 {
				switch __RDX_actions[_acts] {
				case 0:
					{
						mark[nest] = p
					}

				case 1:
					{
						rdx.RdxType = RdxInt
						rdx.Text = data[mark[nest]:p]
					}

				case 2:
					{
						if rdx.RdxType != RdxInt {
							rdx.RdxType = RdxRef
						}
						rdx.Text = data[mark[nest]:p]
					}

				case 3:
					{
						rdx.RdxType = RdxString
						rdx.Text = data[mark[nest]:p]
					}

				case 4:
					{
						rdx.RdxType = RdxName
						rdx.Text = data[mark[nest]:p]
					}

				case 5:
					{
						n := rdx.Nested
						n = append(n, RDX{Parent: rdx})
						rdx.Nested = n
						rdx.RdxType = RdxMap
						rdx = &n[len(n)-1]
						nest++
					}

				case 6:
					{
						if rdx.Parent == nil {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						nest--
						rdx = rdx.Parent
						if rdx.RdxType != RdxSet && rdx.RdxType != RdxMap && rdx.RdxType != RdxObject {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						if len(rdx.Nested) == 1 {
							rdx.RdxType = RdxSet
						}
					}

				case 7:
					{
						n := rdx.Nested
						n = append(n, RDX{Parent: rdx})
						rdx.Nested = n
						rdx.RdxType = RdxArray
						rdx = &n[len(n)-1]
						nest++
					}

				case 8:
					{
						if rdx.Parent == nil {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						nest--
						rdx = rdx.Parent
						if rdx.RdxType != RdxArray {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
					}

				case 9:
					{
						if rdx.Parent == nil {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						n := rdx.Parent.Nested
						if rdx.Parent.RdxType == RdxMap {
							if len(n) == 1 {
								rdx.Parent.RdxType = RdxSet
							} else if (len(n) & 1) == 1 {
								cs = _RDX_error
								{
									p += 1
									goto _out

								}

							}
						}
						n = append(n, RDX{Parent: rdx.Parent})
						rdx.Parent.Nested = n
						rdx = &n[len(n)-1]
					}

				case 10:
					{
						if rdx.Parent == nil {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						n := rdx.Parent.Nested
						if rdx.Parent.RdxType == RdxMap {
							if (len(n) & 1) == 0 {
								cs = _RDX_error
								{
									p += 1
									goto _out

								}

							}
						} else if rdx.Parent.RdxType == RdxObject {
							if (len(n) & 1) == 0 {
								cs = _RDX_error
								{
									p += 1
									goto _out

								}

							}
							if rdx.RdxType != RdxName {
								cs = _RDX_error
								{
									p += 1
									goto _out

								}

							}
						} else {
							cs = _RDX_error
							{
								p += 1
								goto _out

							}

						}
						n = append(n, RDX{Parent: rdx.Parent})
						rdx.Parent.Nested = n
						rdx = &n[len(n)-1]
					}

				}
				_nacts -= 1
				_acts += 1

			}

		}
		if p == eof {
			if cs >= 21 {
				goto _out

			}

		} else {
			if cs != 0 {
				p += 1
				goto _resume

			}

		}
	_out:
		{

		}

	}
	if cs < _RDX_first_final {
		err = fmt.Errorf("RDX parsing failed at pos %d", p)
	}

	return
}
