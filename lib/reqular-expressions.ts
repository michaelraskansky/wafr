export class RegularExpressions {
    public name: string;
    public patterns: string[];

    public static phpSystem = [
        "(print|system)(.*)"
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
        "%2F%2F"
    ]
    public static mlTagsToBlock = [
        "href",
        "form",
        "script",
        "svg",
        "javascript",
        "img"
    ]

    public static commandsToBlock = [
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
        "sleep",
        "kill",
        "ps",
        "bash",
        "ping",
        "sh",
        "expr",
    ]

    public static htmlTagsRegex = [
        `(?:<)(${RegularExpressions.mlTagsToBlock.join("|")})(?:$|\W)`
    ]

    public static commandsRegex = [
        `(?:^|\\W*|;|'|&|\\|)(${RegularExpressions.commandsToBlock.join("|")})(?:$|\\W)`,
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