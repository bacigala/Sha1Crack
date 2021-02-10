# SHA1 crack

## SHA1 implementation (sha1.hpp)
* https://github.com/983/SHA1

## Simple use
* input: one SHA1 hash, output: found password
* brute-force tries all combinations of small letters, capital letters and digits
* e.g. `sha1crack.exe 59b7bc438df4f2c39736f84add54036f2083ef60`

## Command line options
### Salt
* password generator tries to add salt to generated passwords (to the beginning and to the end)
  * when salt `salt` is defined and password `PASSWORD` generated, program checks if `saltPASSWORD` or `PASSWORDsalt` matches the hash
* define with `--salt` or `–S`
  * e.g. `sha1crack.exe --salt thisIsSalt 59b7bc438df4f2c39736f84add54036f2083ef60`

### Input from file
* program tries to crack passwords from the file
* input file format: 1 line = 1 hash
* define with `--input` or `-I`
  * e.g. `sha1crack.exe --input inputFile.txt 59b7bc438df4f2c39736f84add54036f2083ef60`
  
### Pattern
* program tries only passwords matching the pattern
  * `\A` - capital letters
  * `\a` - small letters
  * `\d` - digits
  * `?` - anything from above
  * symbol without preceding `\` defines that symbol at the position
* repetition of a symbol in a pattern can be defined using __range definition__ `{x,y}` or __wildcard__ `*`
  * range e.g. `\a{1,3}B` represents patterns `\aB`, `\a\aB` and `\a\a\aB`
  * wildcard `*` represents any number of occurrences of preceding symbol, it is interpreted as range `{0,MAX_PASSWORD_LENGTH}`
* define with `--pattern` or `-P`
  * e.g. `sha1crack.exe -P \a\a\A{0,3}?* inputFile.txt 59b7bc438df4f2c39736f84add54036f2083ef60`
  
### Dictionary
* program tries passwords defined in dictionary before brute-force
* dictionary file format: 1 line = 1 password
* define with `--dictionary` or `-D`
  * e.g. `sha1crack.exe --D dictionary.txt 59b7bc438df4f2c39736f84add54036f2083ef60`
  
### Multithread processing
* program uses more threads to crack passwords
* use with `-MT`
  * e.g. `sha1crack.exe --I input.txt -MT 59b7bc438df4f2c39736f84add54036f2083ef60`
* __current implementation: 1 hash = 1 thread__ (so using `-MT` with 1 hash input makes no difference in performance :neutral_face:)
  
