import * as fs from 'fs';
import _ = require('lodash');

export class RegularExpressions {
    public name: string;
    public patterns: string[];
    //https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
    public static phpSystem = [
        "(print|system|confirm|alert)(.*)"
    ]
    public static mlTagsToBlock = fs.readFileSync('patterns/ml_tags.txt', 'utf8').split("\n")
    public static eventHandlers = fs.readFileSync('patterns/event_handlers.txt', 'utf8').split("\n")
    public static commandsToBlock = fs.readFileSync('patterns/commands.txt', 'utf8').split("\n")
    public static directoryTraversal = [
        "(page|directory)%3D(..|%2F)(.*)",
        "(page|directory)=(..|\/)(.*)",
        "..%2F",
        "...%2F",
        "file%3A%2F%2F",
        "%5C(.*)",
        "%2F..%2F",
        ".%2F",
        "%2F%2F",
    ]

    public static htmlTagsRegex = [
        `(?:<|&lt;)(${RegularExpressions.mlTagsToBlock.join("|")})(?:$|\\W)`,
        `(?:^|\\W*|;|'|&|\\|)(${RegularExpressions.eventHandlers.join("|")})(?:$|\\W)`,
        "(\\/\\*|\/\/)",
        "(\\/bin|\\/passwd)",
    ]

    public static commandsRegex = [
        `(?:^|\\W*|;|'|&|\\|)(?:\\b)(${RegularExpressions.commandsToBlock.join("|")})(?:$|\\s|&|\\+)`,
        `(\\/\\?\\?\\?\\/)`
    ]

    constructor(name: string, patterns: string[]) {
        this.name = name;
        this.patterns = patterns
    }

    public static regex(): RegularExpressions[] {

        return [
            new RegularExpressions("DirectoryTraversal", RegularExpressions.directoryTraversal),
            new RegularExpressions("HtmlTags", RegularExpressions.htmlTagsRegex),
            new RegularExpressions("Commands", RegularExpressions.commandsRegex),
            new RegularExpressions("PhpSystem", RegularExpressions.phpSystem),
        ]

    }
}