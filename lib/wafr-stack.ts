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
  public static allHtmlTags = ["(%3C)(.*)(%3C)(.*)(%2F%3E)", "(%3C)(.*)(%3C%2F)(.*)(%3E)", "(%3C)(.*)(%2F%3E)", "(.?)%3A%3A(.?)"]
  public static phpSystem = ["(print|system)(.*)"]
  public static directoryTraversal = ["(page|directory)%3D(..|%2F)(.*)", "(page|directory)=(..|\/)(.*)"]
  public static commandAppender = ["(%3B|%7C|%26)"]
  public static commands = ["(ls|cat|nc|echo|cat|rm|nmap|route|netstat|open|ypdomainname|nisdomainname|domainname|dnsdomainname|hostname|grep|find|mv|pwd|sleep|kill|ps|bash|ping|sh|expr)"]

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
    ]

    for (let x of ruleGroups) {
      new wafv2.CfnRuleGroup(this, `RuleGroup${x.name}`, {
        name: `RuleGroup${x.name}`,
        scope: "REGIONAL",
        capacity: x.capacity,
        rules: [
          {
            name: x.name,
            visibilityConfig: {
              metricName: x.name,
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
          metricName: x.name
        }
      })
    }
  }
}
