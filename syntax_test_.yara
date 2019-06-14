// SYNTAX TEST "yara.sublime-syntax"
import "pe"
// <- keyword.control.import
include "other.yar"
// <- keyword.control.import

private rule ExampleRule
// <- keyword.operator.word
//      ^^^^ keyword.operator.word
{
    meta:
//  ^^^^ keyword.operator.word
        description = "test rule"
//                    ^ string.quoted.double
//                              ^ punctuation.definition.string.end
    strings:
//  ^^^^^^^ keyword.operator.word
        $re = /md5: [0-9a-fA-F]{32}/
//            ^ punctuation.definition.regex.begin
//                                 ^ punctuation.definition.regex.end
        $my_text_string = "text \"here"
        $my_hex_string = { E2 34 A1 C8 23 FB }
                      // ^ definition.constant.numeric
                        // ^^^^^^^^^^^^^^^^^^ constant.numeric
        /*
//      ^ punctuation.definition.block.comment.begin
            comment block here
        */
//      ^ punctuation.definition.block.comment.end
        $xor_string = "This program cannot" xor wide
                                         // ^^^ keyword.operator.word
                                             // ^^^^ keyword.operator.word
        $wide_and_ascii_string = "Borland" wide ascii
        $text_string = "foobar" nocase
        $hex_string = {F4 23 ( 62 B4 | 56 | 45 ?? 67 ) 45}
    condition:
        any of them
}
