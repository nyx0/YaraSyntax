// SYNTAX TEST "yara.sublime-syntax"

private rule ExampleRule
// <- keyword.operator.word.yara
//      ^^^^ keyword.operator.word.yara
{
    meta:
//  ^^^^ keyword.operator.word.yara
        description = "test rule"
//                    ^ string.quoted.double
//                              ^ punctuation.definition.string.end
    strings:
//  ^^^^^^^ keyword.operator.word.yara
        $re2 = /state: (on|off)/
        $re1 = /md5: [0-9a-fA-F]{32}/
//             ^ punctuation.definition.regex.begin.yara
//                                  ^ punctuation.definition.regex.end.yara punctuation.definition.regex.begin.yara

        $my_text_string = "text here"
        $my_hex_string = { E2 34 A1 C8 23 FB }
                      // ^ definition.constant.numeric.yara
                        // ^^^^^^^^^^^^^^^^^^ constant.numeric.yara
        $xor_string = "This program cannot" xor wide
                                         // ^^^ keyword.operator.word.yara
                                             // ^^^^ keyword.operator.word.yara
        $wide_and_ascii_string = "Borland" wide ascii
        $text_string = "foobar" nocase
        $hex_string = {F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45}
    condition:
        any of them
}
