// SYNTAX TEST "yara.sublime-syntax"
import "pe"
// <- keyword.control.import
include "other.yar"
// <- keyword.control.import

private rule ExampleRule
//^^^^^ support.type.yara
//      ^^^^ support.function.builtin.yara
{
    meta:
//  ^^^^ support.function.builtin.yara
        description = "test rule"
//                    ^ punctuation.definition.string.begin.yara
//                     ^^^^^^^^^ string.quoted.double.yara
//                              ^ punctuation.definition.string.end.yara
    strings:
//  ^^^^^^^ support.function.builtin.yara
        $re = /md5: [0-9a-fA-F]{32}/ /* test */
//            ^ punctuation.definition.regex.begin.yara
//                                 ^ punctuation.definition.regex.end.yara
//                                   ^^ comment.block.yara punctuation.definition.block.comment.begin.yara
//                                      ^^^^^^^ comment.block.yara
//                                           ^^ comment.block.yara punctuation.definition.block.comment.end.yara
        $text_string = "foobar"
//                     ^ punctuation.definition.string.begin.yara
//                      ^^^^^^ string.quoted.double.yara
//                            ^ punctuation.definition.string.end.yara
//                              
        $hex_string = { E2 34 ?? C8 A? FB }
//                    ^ definition.constant.numeric.begin.yara
//                      ^^^^^^^^^^^^^^^^^^ constant.numeric.yara
//                                        ^ definition.constant.numeric.end.yara
        /*
//      ^^ comment.block.yara punctuation.definition.block.comment.begin.yara
            comment block here
        */
//      ^^ comment.block.yara punctuation.definition.block.comment.end.yara
        $xor_string = "This program cannot" xor wide
//                                          ^^^ support.type.yara
//                                              ^^^^ support.type.yara
        $wide_and_ascii_string = "Borland" wide ascii
//                                         ^^^^ support.type.yara
//                                              ^^^^^ support.type.yara
        $text_string = "foobar" nocase
//                              ^^^^^^ support.type.yara
    condition:
//  ^^^^^^^^^ support.function.builtin.yara
        any of them
//      ^^^ entity.name.yara
//          ^^ entity.name.yara
//             ^^^^ entity.name.yara
