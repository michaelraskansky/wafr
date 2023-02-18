export class RegularExpressions {
    public name: string;
    public patterns: string[];
    //https://hacken.io/discover/how-to-bypass-waf-hackenproof-cheat-sheet/
    public static phpSystem = [
        "(print|system|confirm|alert)(.*)"
    ]
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
    public static mlTagsToBlock = [
        "href",
        "form",
        "script",
        "svg",
        "label",
        "input",
        "javascript",
        "embed",
        "iframe",
        "details",
        "img",
        "body",
        "html",
        "object",
        "isindex",
        "audio",
        "video",
    ]

    public static eventHandlers = [
        "ontoggle",
        "onauxclick",
        "ondblclick",
        "oncontextmenu",
        "onmouseleave",
        "ontouchcancel",
    ]
    public static commandsToBlock = [
        "sbin",
        "wget",
        "ls",
        "cat",
        "nc",
        "echo",
        "cat",
        "rm",
        "nmap",
        "route",
        "netstat",
        "open",
        "ypdomainname",
        "nisdomainname",
        "domainname",
        "dnsdomainname",
        "hostname",
        "grep",
        "find",
        "mv",
        "pwd",
        "kill",
        "ps",
        "bash",
        "ping",
        "sh",
        "expr"
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

    public static commandAppender = [
        "(%3B|%7C|%26|%60)"
    ]

    constructor(name: string, patterns: string[]) {
        this.name = name;
        this.patterns = patterns
    }

    public static regex(): RegularExpressions[] {
        return [
            new RegularExpressions("DirectoryTraversal", RegularExpressions.directoryTraversal),
            new RegularExpressions("HtmlTags", RegularExpressions.htmlTagsRegex),
            new RegularExpressions("CommandAppender", RegularExpressions.commandAppender),
            new RegularExpressions("Commands", RegularExpressions.commandsRegex),
            new RegularExpressions("PhpSystem", RegularExpressions.phpSystem),
        ]

    }
}