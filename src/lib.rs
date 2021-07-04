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

	let heap_size = find_heap_lines(&file)
		.into_iter()
		.map(|range| range.end - range.start)
		.sum();

	Ok(heap_size)
}

fn find_heap_lines(buf: &str) -> Vec<Range<usize>> {
	buf.lines()
		.filter_map(|line| recognize_heap(line).ok())
		.map(|(_tail, range)| range)
		.collect::<Vec<_>>()
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
}
