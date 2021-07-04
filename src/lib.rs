use nom::bytes::complete::{is_a, tag};
use nom::character::complete::{hex_digit1, multispace1};
use nom::combinator::map_res;
use nom::lib::std::ops::Range;
use nom::sequence::separated_pair;
use nom::IResult;
use std::io;

pub fn read_heap_size(pid: Option<u64>) -> Result<usize, io::Error> {
	let file = std::fs::read_to_string(format!(
		"/proc/{}/maps",
		pid.map(|pid| pid.to_string()).as_deref().unwrap_or("self")
	))?;

	Ok(sum_heap_lines(&file))
}

fn sum_heap_lines(buf: &str) -> usize {
	buf.lines()
		.filter_map(|line| recognize_heap(line).ok())
		.map(|(_tail, range)| range.end - range.start)
		.sum()
}

fn recognize_heap(line: &str) -> IResult<&str, Range<usize>> {
	let (tail, (min, max)) = separated_pair(
		map_res(hex_digit1, |num| usize::from_str_radix(num, 16)),
		tag("-"),
		map_res(hex_digit1, |num| usize::from_str_radix(num, 16)),
	)(line)?;

	let (tail, _) = multispace1(tail)?;
	let (tail, _) = is_a("rwpx-")(tail)?;
	let (tail, _) = multispace1(tail)?;
	let (tail, _) = tag("00000000")(tail)?;
	let (tail, _) = multispace1(tail)?;
	let (tail, _) = tag("00:00")(tail)?;
	let (tail, _) = multispace1(tail)?;
	let (tail, _) = tag("0")(tail)?;

	Ok((tail, min..max))
}

#[cfg(test)]
mod tests {
	use super::*;
	use cool_asserts::assert_matches;

	#[test]
	fn heap_region() {
		let input = "7ff6ad5f8000-7ff6ad7f5000 rw-p 00000000 00:00 0";
		assert_matches!(recognize_heap(input), Ok((_, range))
			if range.start == 0x7ff6ad5f8000 && range.end ==0x7ff6ad7f5000
		)
	}

	#[test]
	fn non_heap_region() {
		let input = "7ff6ad5f8000-7ff6ad7f5000 rw-p 00037000 fd:01 23470072";
		assert_matches!(recognize_heap(input), Err(_));
	}

	#[test]
	fn test_sum_heap_lines() {
		assert_eq!(sum_heap_lines(EXAMPLE_MAPS), 3494903808);
	}

	const EXAMPLE_MAPS: &str = r###"414ef000-4159e000 rw-p 00000000 00:00 0
416da000-416dc000 r-xs 00000000 00:01 2295                               /memfd:/.glXXXXXX (deleted)
83000000-a9793000 rw-p 00000000 00:00 0
a9793000-100000000 ---p 00000000 00:00 0
100000000-102b82000 rw-p 00000000 00:00 0
102b82000-140000000 ---p 00000000 00:00 0
5650a3a00000-5650a3a01000 r-xp 00000000 fd:01 23470129                   /usr/bin/java
5650a3c01000-5650a3c02000 r--p 00001000 fd:01 23470129                   /usr/bin/java
5650a3c02000-5650a3c03000 rw-p 00002000 fd:01 23470129                   /usr/bin/java
5650a4d0a000-5650a4d2b000 rw-p 00000000 00:00 0                          [heap]
7ff6acdf0000-7ff6acdf4000 ---p 00000000 00:00 0
7ff6acdf4000-7ff6acff1000 rw-p 00000000 00:00 0
7ff6ad5f4000-7ff6ad5f8000 ---p 00000000 00:00 0
7ff6ad5f8000-7ff6ad7f5000 rw-p 00000000 00:00 0
7ff6ad7f5000-7ff6ad7f9000 ---p 00000000 00:00 0
7ff6ad7f9000-7ff6ad9f6000 rw-p 00000000 00:00 0
7ff6adbf7000-7ff6adbfb000 ---p 00000000 00:00 0
7ff6adbfb000-7ff6addf8000 rw-p 00000000 00:00 0
7ff6adff9000-7ff6ae1f9000 rw-p 00000000 00:00 0
7ff6ae1f9000-7ff6ae3f9000 rw-p 00000000 00:00 0
7ff6ae3f9000-7ff6ae5f9000 rw-p 00000000 00:00 0
7ff6ae5f9000-7ff6ae7f9000 rw-p 00000000 00:00 0
7ff6ae7f9000-7ff6ae9f9000 rw-p 00000000 00:00 0
7ff6ae9f9000-7ff6aebf9000 rw-p 00000000 00:00 0
7ff6aebf9000-7ff6aedf9000 rw-p 00000000 00:00 0
7ff6aedf9000-7ff6aeff9000 rw-p 00000000 00:00 0
7ff6afe00000-7ff6b0000000 rw-p 00000000 00:00 0
7ff6b0000000-7ff6b12c3000 rw-p 00000000 00:00 0
7ff6b12c3000-7ff6b4000000 ---p 00000000 00:00 0
7ff6b41bc000-7ff6b43bc000 rw-p 00000000 00:00 0
7ff6b43bc000-7ff6b45bc000 rw-p 00000000 00:00 0
7ff6b45bc000-7ff6b47bc000 rw-p 00000000 00:00 0
7ff6b47bc000-7ff6b49bc000 rw-p 00000000 00:00 0
7ff6b49bc000-7ff6b4bbc000 rw-p 00000000 00:00 0
7ff6b4bbc000-7ff6b4dbc000 rw-p 00000000 00:00 0
7ff6b4dbc000-7ff6b4fbc000 rw-p 00000000 00:00 0
7ff6b4fbc000-7ff6b51bc000 rw-p 00000000 00:00 0
7ff6b53bd000-7ff6b55bd000 rw-p 00000000 00:00 0
7ff6b55bd000-7ff6b57bd000 rw-p 00000000 00:00 0
7ff6b61c7000-7ff6b63c7000 rw-p 00000000 00:00 0
7ff6b63c7000-7ff6b65c7000 rw-p 00000000 00:00 0
7ff6b6dc8000-7ff6b6fc8000 rw-p 00000000 00:00 0
7ff6b6fc8000-7ff6b71c8000 rw-p 00000000 00:00 0
7ff6b71c8000-7ff6b73c8000 rw-p 00000000 00:00 0
7ff6b73c8000-7ff6b75c8000 rw-p 00000000 00:00 0
7ff6b75c8000-7ff6b77c8000 rw-p 00000000 00:00 0
7ff6b77c8000-7ff6b79c8000 rw-p 00000000 00:00 0
7ff6b79c8000-7ff6b79fe000 r-xp 00000000 fd:01 23470072                   /home/aqatl/.local/share/JetBrains/Toolbox/apps/CLion/ch-1/201.8743.17/jbr/lib/libjavajpeg.so
7ff6b79fe000-7ff6b7bfe000 ---p 00036000 fd:01 23470072                   /home/aqatl/.local/share/JetBrains/Toolbox/apps/CLion/ch-1/201.8743.17/jbr/lib/libjavajpeg.so
7ff6b7bfe000-7ff6b7bff000 r--p 00036000 fd:01 23470072                   /home/aqatl/.local/share/JetBrains/Toolbox/apps/CLion/ch-1/201.8743.17/jbr/lib/libjavajpeg.so
7ff6b7bff000-7ff6b7c00000 rw-p 00037000 fd:01 23470072                   /home/aqatl/.local/share/JetBrains/Toolbox/apps/CLion/ch-1/201.8743.17/jbr/lib/libjavajpeg.so
7ff6b7c00000-7ff6b7e00000 rw-p 00000000 00:00 0
7ff6b7e00000-7ff6b8000000 rw-p 00000000 00:00 0
7ff6b8000000-7ff6bbf26000 rw-p 00000000 00:00 0
7ff6bbf26000-7ff6bc000000 ---p 00000000 00:00 0
7ff6bc000000-7ff6bc05a000 rw-p 00000000 00:00 0
7ff6bc05a000-7ff6c0000000 ---p 00000000 00:00 0
7ff6c016d000-7ff6c036d000 rw-p 00000000 00:00 0
7ff6c04f2000-7ff6c06f2000 rw-p 00000000 00:00 0
7ff6c06f2000-7ff6c08f2000 rw-p 00000000 00:00 0
7ff6c08f2000-7ff6c08f3000 ---p 00000000 00:00 0
7ff6c08f3000-7ff6c12f3000 rw-p 00000000 00:00 0
7ff6c12f3000-7ff6c14f3000 rw-p 00000000 00:00 0
7ff6c14f3000-7ff6c16f3000 rw-p 00000000 00:00 0
7ff6c1878000-7ff6c1a78000 rw-p 00000000 00:00 0
7ff6c1a78000-7ff6c1c78000 rw-p 00000000 00:00 0
7ff6c1c78000-7ff6c1e78000 rw-p 00000000 00:00 0
7ff6c1e78000-7ff6c1e79000 ---p 00000000 00:00 0
7ff6c1e79000-7ff6c2679000 rw-p 00000000 00:00 0
7ff6c2679000-7ff6c267d000 ---p 00000000 00:00 0
7ff6c267d000-7ff6c2a7a000 rw-p 00000000 00:00 0
7ff6c2bff000-7ff6c2dff000 rw-p 00000000 00:00 0
7ff6c2dff000-7ff6c2fff000 rw-p 00000000 00:00 0
7ff6c2fff000-7ff6c31ff000 rw-p 00000000 00:00 0
7ff6c31ff000-7ff6c33ff000 rw-p 00000000 00:00 0
7ff6c33ff000-7ff6c35ff000 rw-s 00000000 00:05 714                        /dev/nvidiactl
7ff6c35ff000-7ff6c39ff000 rw-s 00000000 00:05 714                        /dev/nvidiactl
7ff6c39ff000-7ff6c3bff000 rw-s 00000000 00:05 714                        /dev/nvidiactl
7ff6c3bff000-7ff6c3dff000 rw-p 00000000 00:00 0
7ff6c3dff000-7ff6c3e03000 ---p 00000000 00:00 0
7ff6c3e03000-7ff6c4000000 rw-p 00000000 00:00 0
7ff8c72f6000-7ff8c72f7000 r--p 00000000 fd:01 7866373                    /usr/lib/x86_64-linux-gnu/ld-2.33.so
7ff8c72f7000-7ff8c731e000 r-xp 00001000 fd:01 7866373                    /usr/lib/x86_64-linux-gnu/ld-2.33.so
7ff8c731e000-7ff8c7328000 r--p 00028000 fd:01 7866373                    /usr/lib/x86_64-linux-gnu/ld-2.33.so
7ff8c7328000-7ff8c732a000 r--p 00031000 fd:01 7866373                    /usr/lib/x86_64-linux-gnu/ld-2.33.so
7ff8c732a000-7ff8c732c000 rw-p 00033000 fd:01 7866373                    /usr/lib/x86_64-linux-gnu/ld-2.33.so
7ffe99c5a000-7ffe99c7b000 rw-p 00000000 00:00 0                          [stack]
7ffe99d36000-7ffe99d3a000 r--p 00000000 00:00 0                          [vvar]
7ffe99d3a000-7ffe99d3c000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
"###;
}
