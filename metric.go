package dns_check

import(
	"math"
	"math/big"
	"strings"
	"fmt"
	"sort"
	"log"
	"strconv"
)

var round_power int64
var leading_zero bool

const max_pow int = 30
const qsec_pow int64 = -30
var show_all_values bool
var show_all_values_super bool

var leading_zero_start_from_sec bool

type MetricPrefix struct {
	Symbol    string
	Base10    float64
	Pow  int64
	FullName  string
	Adoption  int
}

var MetricAllPrefixes = map[string]MetricPrefix{
	"quetta": {Symbol: "Q", Base10: math.Pow(10, 30), Pow: 30, FullName: "quetta", Adoption: 2022},
	"ronna":  {Symbol: "R", Base10: math.Pow(10, 27), Pow: 27, FullName: "ronna", Adoption: 2022},
	"yotta":  {Symbol: "Y", Base10: math.Pow(10, 24), Pow: 24, FullName: "yotta", Adoption: 1991},
	"zetta":  {Symbol: "Z", Base10: math.Pow(10, 21), Pow: 21, FullName: "zetta", Adoption: 1991},
	"exa":    {Symbol: "E", Base10: math.Pow(10, 18), Pow: 18, FullName: "exa", Adoption: 1975},
	"peta":   {Symbol: "P", Base10: math.Pow(10, 15), Pow: 15, FullName: "peta", Adoption: 1975},
	"tera":   {Symbol: "T", Base10: math.Pow(10, 12), Pow: 12, FullName: "tera", Adoption: 1960},
	"giga":   {Symbol: "G", Base10: math.Pow(10, 9), Pow: 9, FullName: "giga", Adoption: 1960},
	"mega":   {Symbol: "M", Base10: math.Pow(10, 6), Pow: 6, FullName: "mega", Adoption: 1873},
	"kilo":   {Symbol: "k", Base10: math.Pow(10, 3), Pow: 3, FullName: "kilo", Adoption: 1795},
	"hecto":  {Symbol: "h", Base10: math.Pow(10, 2), Pow: 2, FullName: "hecto", Adoption: 1795},
	"deca":   {Symbol: "da", Base10: math.Pow(10, 1), Pow: 1, FullName: "deca", Adoption: 1795},
	"none":   {Symbol: "", Base10: math.Pow(10, 0), Pow: 0, FullName: "none", Adoption: 1795},
	"deci":   {Symbol: "d", Base10: math.Pow(10, -1), Pow: -1, FullName: "deci", Adoption: 1795},
	"centi":  {Symbol: "c", Base10: math.Pow(10, -2), Pow: -2, FullName: "centi", Adoption: 1795},
	"milli":  {Symbol: "m", Base10: math.Pow(10, -3), Pow: -3, FullName: "milli", Adoption: 1795},
	"micro":  {Symbol: "µ", Base10: math.Pow(10, -6), Pow: -6, FullName: "micro", Adoption: 1873},
	"nano":   {Symbol: "n", Base10: math.Pow(10, -9), Pow: -9, FullName: "nano", Adoption: 1960},
	"pico":   {Symbol: "p", Base10: math.Pow(10, -12), Pow: -12, FullName: "pico", Adoption: 1960},
	"femto":  {Symbol: "f", Base10: math.Pow(10, -15), Pow: -15, FullName: "femto", Adoption: 1964},
	"atto":   {Symbol: "a", Base10: math.Pow(10, -18), Pow: -18, FullName: "atto", Adoption: 1964},
	"zepto":  {Symbol: "z", Base10: math.Pow(10, -21), Pow: -21, FullName: "zepto", Adoption: 1991},
	"yocto":  {Symbol: "y", Base10: math.Pow(10, -24), Pow: -24, FullName: "yocto", Adoption: 1991},
	"ronto":  {Symbol: "r", Base10: math.Pow(10, -27), Pow: -27, FullName: "ronto", Adoption: 2022},
	"quecto": {Symbol: "q", Base10: math.Pow(10, -30), Pow: -30, FullName: "quecto", Adoption: 2022},
}

var MetricCommonPrefixes = map[string]MetricPrefix{
	"quetta": {Symbol: "Q", Base10: math.Pow(10, 30), Pow: 30, FullName: "quetta", Adoption: 2022},
	"ronna":  {Symbol: "R", Base10: math.Pow(10, 27), Pow: 27, FullName: "ronna", Adoption: 2022},
	"yotta":  {Symbol: "Y", Base10: math.Pow(10, 24), Pow: 24, FullName: "yotta", Adoption: 1991},
	"zetta":  {Symbol: "Z", Base10: math.Pow(10, 21), Pow: 21, FullName: "zetta", Adoption: 1991},
	"exa":    {Symbol: "E", Base10: math.Pow(10, 18), Pow: 18, FullName: "exa", Adoption: 1975},
	"peta":   {Symbol: "P", Base10: math.Pow(10, 15), Pow: 15, FullName: "peta", Adoption: 1975},
	"tera":   {Symbol: "T", Base10: math.Pow(10, 12), Pow: 12, FullName: "tera", Adoption: 1960},
	"giga":   {Symbol: "G", Base10: math.Pow(10, 9), Pow: 9, FullName: "giga", Adoption: 1960},
	"mega":   {Symbol: "M", Base10: math.Pow(10, 6), Pow: 6, FullName: "mega", Adoption: 1873},
	"kilo":   {Symbol: "k", Base10: math.Pow(10, 3), Pow: 3, FullName: "kilo", Adoption: 1795},
	"none":   {Symbol: "", Base10: math.Pow(10, 0), Pow: 0, FullName: "none", Adoption: 1795},
	"milli":  {Symbol: "m", Base10: math.Pow(10, -3), Pow: -3, FullName: "milli", Adoption: 1795},
	"micro":  {Symbol: "µ", Base10: math.Pow(10, -6), Pow: -6, FullName: "micro", Adoption: 1873},
	"nano":   {Symbol: "n", Base10: math.Pow(10, -9), Pow: -9, FullName: "nano", Adoption: 1960},
	"pico":   {Symbol: "p", Base10: math.Pow(10, -12), Pow: -12, FullName: "pico", Adoption: 1960},
	"femto":  {Symbol: "f", Base10: math.Pow(10, -15), Pow: -15, FullName: "femto", Adoption: 1964},
	"atto":   {Symbol: "a", Base10: math.Pow(10, -18), Pow: -18, FullName: "atto", Adoption: 1964},
	"zepto":  {Symbol: "z", Base10: math.Pow(10, -21), Pow: -21, FullName: "zepto", Adoption: 1991},
	"yocto":  {Symbol: "y", Base10: math.Pow(10, -24), Pow: -24, FullName: "yocto", Adoption: 1991},
	"ronto":  {Symbol: "r", Base10: math.Pow(10, -27), Pow: -27, FullName: "ronto", Adoption: 2022},
	"quecto": {Symbol: "q", Base10: math.Pow(10, -30), Pow: -30, FullName: "quecto", Adoption: 2022},
}

func Digit(z *big.Int, digit int, pos int) {
	// Convert the big integer to a string
	zstr := z.String()

	// Convert the string to a byte slice
	zbytes := []rune(zstr)

	// Modify the digit at the specified position
	zbytes[len(zbytes)-1-pos] = rune(digit)

	// Convert the modified byte slice back to a string
	z.SetString(string(zbytes), 10)
}

var round_on bool

func padRunes(input []rune, length int) []rune {
    if length <= len(input) {
        return input
    }
    padding := make([]rune, length-len(input))
    for i := range padding {
        padding[i] = '0' // Assuming you want to pad with '0's
    }
    return append(padding, input...)
}

func removeSingleTrailingSpace(input string) string {
	// Check if the input string has a single trailing space
	if strings.HasSuffix(input, " ") {
		// If yes, remove the last character
		return input[:len(input)-1]
	}
	// If no trailing space, return the input string as is
	return input
}

func fmt_epoch_to_prefixsec(utime *big.Int, prefixesp *map[string]MetricPrefix, break_prefix string) string {
	var output strings.Builder

	// var fl_time float64

	prefixes := *(prefixesp)

	// if mul != nil {
	// 	fl_time = float64(utime) * *(mul)
	// } else {
	// 	fl_time = float64(utime)
	// }
	str := []rune(utime.String())

	// fmt.Println(utime)


	if round_on {
		// fl_time = math.Floor(fl_time / math.Pow10(int(round_power))) * math.Pow10(int(round_power))
		// fl_time = fl_time - (math.Mod(fl_time, float64(math.Pow10(int(round_power)))))

		// str := utime.String()



		for i := int(round_power+(qsec_pow*-1)); i > 0; i-- {
			str[len(str)-i] = '0'
		}
		// fmt.Println(string(str))
		// utime.SetString(string(zbytes), 10)
	}

	// var fl_round_time float64


	str = padRunes(str, max_pow+int(qsec_pow*-1)+3) // why is +12 needed?


	keys := make([]string, 0, len(prefixes))
	for key := range prefixes {
		keys = append(keys, key)
	}

	// Sort the keys in descending order
	sort.Slice(keys, func(i, j int) bool {
		return prefixes[keys[i]].Base10 > prefixes[keys[j]].Base10
	})



	var value MetricPrefix
	var next_value MetricPrefix
	var powerDifference int64

	var rem_amount int64

	var first_non0 bool = false
	// Iterate over the sorted keys

	// var last_power int64
	// stln := int64(len(str))
	var tmp string
	// var tmpn int
	var t int
	var sl_tmpn []int
	var err error
	var val_hasval bool
	for i, key := range keys {
		sl_tmpn = []int{}
		value = prefixes[key]
		val_hasval = false

		if i+1 < len(prefixes) {
			next_value = prefixes[keys[i+1]]

			// powerDifference = math.Log10(value.Base10) - math.Log10(next_value.Base10)
			powerDifference = value.Pow - next_value.Pow
		} else {
			powerDifference = 3
		}

		if len(str) < int(powerDifference) {
			break
		}

		rem_amount = powerDifference


		for ; (len(str) - max_pow) > int(value.Pow) ; {
			tmp = string(str[:int(rem_amount)])

			t, err = strconv.Atoi(tmp)
			if err != nil {
				// break
				log.Fatal(err)
			}

			sl_tmpn = append(sl_tmpn, t)
			str = str[int(rem_amount):]
		}



		for _, tmpn := range sl_tmpn {
			if tmpn != 0 || (show_all_values && first_non0) || show_all_values_super {

				// fmt.Println(tmpn)

				if leading_zero && ((!(leading_zero_start_from_sec && !first_non0))) {
					// formatString := fmt.Sprintf("%%0%d.0f%%v", int(powerDifference))
					// fmt.Println(formatString)
					output.WriteString(fmt.Sprintf("%0*d", powerDifference ,tmpn))
				} else {
					output.WriteString(fmt.Sprintf("%v",tmpn))
				}
				val_hasval = true
				// output.WriteString(tmp)
				// output.WriteString(value.Symbol+"s ")

				first_non0 = true
			}

		}

		if val_hasval {
			output.WriteString(value.Symbol+"s ")
		}



		if key == break_prefix {
			break
		}

	}

	return strings.TrimSpace(output.String())
	// return removeSingleTrailingSpace(output.String())
}


