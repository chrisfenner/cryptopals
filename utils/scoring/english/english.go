package english

import "fmt"

var (
	// https://en.wikipedia.org/wiki/Letter_frequency
	englishFrequencies = map[byte]float64{
		'a': .08167,
		'b': .01492,
		'c': .02782,
		'd': .04253,
		'e': .12702,
		'f': .02228,
		'g': .02015,
		'h': .06094,
		'i': .06966,
		'j': .00153,
		'k': .00772,
		'l': .04025,
		'm': .02406,
		'n': .06749,
		'o': .07507,
		'p': .01929,
		'q': .00095,
		'r': .05987,
		's': .06327,
		't': .09506,
		'u': .02758,
		'v': .00978,
		'w': .02630,
		'x': .00150,
		'y': .01974,
		'z': .00074,
	}
)

// letter checks if a character is an ASCII letter and returns the lowercase form.
// If the character is not a letter, returns false.
func letter(c byte) (byte, bool) {
	if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
		// uppercase letters are A=0x41, B=0x42, ...
		// lowercase letters are a=0x61, b=0x62, ...
		// force lowercase by setting the 0x20 bit
		return c | 0x20, true
	}
	return c, false
}

// returns whether the character is ASCII printable
func ascii(c byte) bool {
	return (c >= 0x20 && c <= 0x7e) || c == 0x09 // tab is printable
}

// buildFrequencyTable builds a table of frequencies of the letters in text. Non-letters are
// ignored. The presence of non-ASCII-printable characters returns an error.
func buildFrequencyTable(text string) (map[byte]float64, error) {
	letterCount := 0
	counts := make(map[byte]float64)
	for i := range text {
		if l, ok := letter(text[i]); ok {
			letterCount++
			counts[l]++
		} else if !ascii(text[i]) {
			return nil, fmt.Errorf("unprintable character %x at index %v", text[i], i)
		}
	}
	// divide all the counts by the number of letters to get relative frequencies
	for l, f := range counts {
		counts[l] = f / float64(letterCount)
	}
	return counts, nil
}

// Variance returns the variance of the letter character frequencies present in the given text.
// Punctuation characters are ignored.
// The presence of non-ASCII-printable characters returns an error.
func Variance(text string) (float64, error) {
	table, err := buildFrequencyTable(text)
	if err != nil {
		return 0, err
	}
	variance := float64(0)
	for l, f := range table {
		difference := englishFrequencies[l] - f
		variance += (difference * difference)
	}
	return variance, nil
}
