import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

/**
 * TODO:
 */
class RegexPatter {
  public name: string;
  public patterns: string[];

  // Regex
  public static allHtmlTags = [
    "(%3C)(.*)(%3C)(.*)(%2F%3E)",
    "(%3C)(.*)(%3C%2F)(.*)(%3E)",
    "(%3C)(.*)(%2F%3E)",
    "%5BinnerHTML%5D",
    "javascript%3A",
    "%26lt%3Bscript%26gt%3B",
    "&lt;/script&gt;",
    "alert()",
    "(alert)()",
    "%26lt%3B%2Fscript%26gt%3B",
    "__proto__",
    "<(?:\\w+)\\W+?[\\w]",
    // https://github.com/s0md3v/AwesomeXSS
    encodeURI("<A/hREf=\"j%0aavas%09cript%0a:%09con%0afirm%0d``\">z"),
    encodeURI("<d3\"<\"/onclick=\"1>[confirm``]\"<\">z"),
    encodeURI("<d3/onmouseenter=[2].find(confirm)>z"),
    encodeURI("<details open ontoggle=confirm()>"),
    encodeURI("<script y=\"><\">/*<script* */prompt()</script"),
    encodeURI("<w=\"/x=\"y>\"/ondblclick=`<`[confir\u006d``]>z"),
    encodeURI("<a href=\"javascript%26colon;alert(1)\">click"),
    encodeURI("<a href=javas&#99;ript:alert(1)>click"),
    encodeURI("<script/\"<a\"/src=data:=\".<a,[8].some(confirm)>"),
    encodeURI("<svg/x=\">\"/onload=confirm()//"),
    encodeURI("<--`<img/src=` onerror=confirm``> --!>"),
    encodeURI("<svg%0Aonload=%09((pro\u006dpt))()//"),
    encodeURI("<sCript x>(((confirm)))``</scRipt x>"),
    encodeURI("<svg </onload =\"1> (_=prompt,_(1)) \"\">"),
    encodeURI("<!--><script src=//14.rs>"),
    encodeURI("<embed src=//14.rs>"),
    encodeURI("<script x=\">\" src=//15.rs></script>"),
    encodeURI("<!'/*\"/*/'/*/\"/*--></Script><Image SrcSet=K */; OnError=confirm`1` //>"),
    encodeURI("<iframe/src \/\/onload = prompt(1)"),
    encodeURI("<x oncut=alert()>x"),
    encodeURI("<svg onload=write()>"),
    encodeURI("<svg onload=alert()>"),
    encodeURI("</tag><svg onload=alert()>"),
    encodeURI("><svg onload=alert()>"),
    encodeURI("><svg onload=alert()><b attr="),
    encodeURI(" onmouseover=alert() "),
    encodeURI("onmouseover=alert()//"),
    encodeURI("autofocus/onfocus=\"alert()"),
    "ontoggle",
    "onauxclick",
    "ondblclick",
    "oncontextmenu",
    "onmouseleave",
    "ontouchcancel",
    "(.?)%3A%3A(.?)"
  ]
  public static phpSystem = ["(print|system)(.*)"]
  public static directoryTraversal = [
    "(page|directory)%3D(..|%2F)(.*)",
    "(page|directory)=(..|\/)(.*)",
    "..%2F",
    "...%2F",
    "file%3A%2F%2F",
    "\\\\",
    "/../",
    "./",
    "//"
  ]
  public static commandAppender = ["(%3B|%7C|%26|%60)"]
  public static commands = ["(%2Fusr|%2Fsbin|%2Fbin|wget|ls|cat|nc|echo|cat|rm|nmap|route|netstat|open|ypdomainname|nisdomainname|domainname|dnsdomainname|hostname|grep|find|mv|pwd|sleep|kill|ps|bash|ping|sh|expr)"]

  constructor(name: string, patterns: string[]) {
    this.name = name;
    this.patterns = patterns
  }
  static new(name: string, patterns: string[],): RegexPatter {
    return new RegexPatter(name, patterns)
  }
}
class RuleGroup {
  public name: string;
  public patterns: string[];
  public capacity: number;
  public statment: wafv2.CfnRuleGroup.StatementProperty
  public fieldToMatch: wafv2.CfnRuleGroup.FieldToMatchProperty;
  public textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[];

  // Matchers
  public static MatchAllQueryArguments = { allQueryArguments: {} }
  public static MatchQueryString = { queryString: {} }
  public static MatchBodyMatchOversize = { body: { oversizeHandling: "MATCH" } }
  public static MatchBodyNoMatchOversize = { body: { oversizeHandling: "NO_MATCH" } }


  // Transformations
  public static TransformUrlDecode: wafv2.CfnRuleGroup.TextTransformationProperty = { priority: 0, type: "URL_DECODE" }
  public static TransformCommandLine: wafv2.CfnRuleGroup.TextTransformationProperty = { priority: 0, type: "CMD_LINE" }
  public static TransformNone: wafv2.CfnRuleGroup.TextTransformationProperty = { priority: 0, type: "NONE" }

  constructor(name: string, capacity: number, statment: wafv2.CfnRuleGroup.StatementProperty) {
    this.name = name;
    this.statment = statment
    this.capacity = capacity
  }
}
let regularExpressions: RegexPatter[] = [
  new RegexPatter("DirectoryTraversal", RegexPatter.directoryTraversal),
  new RegexPatter("AllHtmlTags", RegexPatter.allHtmlTags),
  new RegexPatter("CommandAppender", RegexPatter.commandAppender),
  new RegexPatter("Commands", RegexPatter.commands),
  new RegexPatter("PhpSystem", RegexPatter.phpSystem),
]

export class WafrStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    let regexMap: { [key: string]: string; } = {}
    let rules: wafv2.CfnWebACL.RuleProperty[] = []

    for (let x of regularExpressions) {
      let regex = new wafv2.CfnRegexPatternSet(this, `RuleSet${x.name}`, {
        scope: "REGIONAL",
        name: x.name,
        regularExpressionList: x.patterns
      })
      regexMap[x.name] = regex.attrArn
    }

    let ruleGroups: RuleGroup[] = [
      new RuleGroup("DirectoryTraversal", 25, {
        regexPatternSetReferenceStatement: {
          arn: regexMap["DirectoryTraversal"],
          fieldToMatch: RuleGroup.MatchQueryString,
          textTransformations: [RuleGroup.TransformNone]
        }
      }),

      new RuleGroup("DisallowHtmlInForms", 25, {
        regexPatternSetReferenceStatement: {
          arn: regexMap["AllHtmlTags"],
          fieldToMatch: RuleGroup.MatchBodyMatchOversize,
          textTransformations: [RuleGroup.TransformNone]
        }
      }),

      new RuleGroup("PhpSystem", 35, {
        regexPatternSetReferenceStatement: {
          arn: regexMap["PhpSystem"],
          fieldToMatch: RuleGroup.MatchAllQueryArguments,
          textTransformations: [RuleGroup.TransformNone]
        }
      }),

      new RuleGroup("SqliHighSensetivity", 110, {
        andStatement: {
          statements: [
            {
              sqliMatchStatement: {
                fieldToMatch: RuleGroup.MatchAllQueryArguments,
                sensitivityLevel: "HIGH",
                textTransformations: [
                  { priority: 0, type: "URL_DECODE_UNI" },
                  { priority: 1, type: "COMPRESS_WHITE_SPACE" }
                ]
              },
            },
            {
              sqliMatchStatement: {
                fieldToMatch: RuleGroup.MatchBodyMatchOversize,
                sensitivityLevel: "HIGH",
                textTransformations: [
                  { priority: 0, type: "URL_DECODE_UNI" },
                  { priority: 1, type: "COMPRESS_WHITE_SPACE" }
                ]
              },
            }
          ]
        }
      }),

      new RuleGroup("PostEscapeCommand", 60, {
        andStatement: {
          statements: [
            {
              regexPatternSetReferenceStatement: {
                arn: regexMap["CommandAppender"],
                fieldToMatch: RuleGroup.MatchBodyMatchOversize,
                textTransformations: [RuleGroup.TransformNone]
              }
            },
            {
              regexPatternSetReferenceStatement: {
                arn: regexMap["Commands"],
                fieldToMatch: RuleGroup.MatchBodyMatchOversize,
                textTransformations: [RuleGroup.TransformCommandLine]
              }
            }
          ]
        }
      }),

      new RuleGroup("XmlHtmlAllTags", 35, {
        regexPatternSetReferenceStatement: {
          arn: regexMap["AllHtmlTags"],
          fieldToMatch: RuleGroup.MatchAllQueryArguments,
          textTransformations: [RuleGroup.TransformNone]
        }
      }),

      new RuleGroup("XssHandlingNative", 110, {
        xssMatchStatement: {
          fieldToMatch: RuleGroup.MatchAllQueryArguments,
          textTransformations: [
            { priority: 0, type: "COMPRESS_WHITE_SPACE" }
          ]
        }
      }),
    ]

    for (let i = 0; i < ruleGroups.length; i++) {
      let x = ruleGroups[i]
      let rg = new wafv2.CfnRuleGroup(this, `RuleGroup${x.name}`, {
        name: `RuleGroup${x.name}`,
        scope: "REGIONAL",
        capacity: x.capacity,
        rules: [
          {
            name: x.name,
            visibilityConfig: {
              metricName: `Rule${x.name}`,
              sampledRequestsEnabled: true,
              cloudWatchMetricsEnabled: true,
            },
            priority: 0,
            action: {
              block: {}
            },
            statement: x.statment
          }
        ],
        visibilityConfig: {
          sampledRequestsEnabled: true,
          cloudWatchMetricsEnabled: true,
          metricName: `RuleGroup${x.name}`
        }
      })

      rules.push({
        name: `${x.name}`,
        priority: i,
        overrideAction: {
          none: {
          }
        },
        visibilityConfig: {
          sampledRequestsEnabled: true,
          cloudWatchMetricsEnabled: true,
          metricName: `RuleWebAcl${x.name}`
        },
        statement: {
          ruleGroupReferenceStatement: {
            arn: rg.attrArn,
          }
        }
      })
    }

    new wafv2.CfnWebACL(this, "CdkAcl", {
      defaultAction: {
        allow: {
        }
      },
      scope: "REGIONAL",
      rules: rules,
      visibilityConfig: {
        cloudWatchMetricsEnabled: true,
        metricName: "CdkAcl",
        sampledRequestsEnabled: true
      }
    })
  }
}
