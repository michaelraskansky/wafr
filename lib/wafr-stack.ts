import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as wafv2 from 'aws-cdk-lib/aws-wafv2';

/**
 * - capacity limit errors
 * - need to double check that the rules match correctly (body, query) looks like some to not fit the reference
 */
class RegexPatter {
  public name: string;
  public patterns: string[];
  public capacity: number;
  public fieldToMatch: wafv2.CfnRuleGroup.FieldToMatchProperty;
  public textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[];

  // Matchers
  public static MatchAllQueryArguments = { allQueryArguments: {} }
  public static MatchBodyMatchOversize = { body: { oversizeHandling: "MATCH" } }
  public static MatchBodyNoMatchOversize = { body: { oversizeHandling: "NO_MATCH" } }

  // Transformations
  public static TransformUrlDecode = [{ priority: 0, type: "URL_DECODE" }]

  // Regex
  public static allHtmlTags = ["(%3C)(.*)(%3C)(.*)(%2F%3E)", "(%3C)(.*)(%3C%2F)(.*)(%3E)", "(%3C)(.*)(%2F%3E)"]
  public static phpSystem = ["(print|system)%28(.*)%29"]
  public static phpInfo = ["phpinfo.php"]
  public static directoryTraversal = ["(page|directory)=(..|\\/)(.*)"]
  public static commands = ["(\\s*)(%3B|%7C|%26)(\\s*)(ls|cat|nc|echo|cat|rm|nmap|route|netstat|open|ypdomainname|nisdomainname|domainname|dnsdomainname|hostname|grep|find|mv|pwd|sleep|kill|ps|bash|ping|sh|expr)"]

  constructor(name: string, capacity: number, patterns: string[], fieldToMatch: wafv2.CfnRuleGroup.FieldToMatchProperty, textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[] = [{ priority: 0, type: "NONE" }]) {
    this.name = name;
    this.patterns = patterns
    this.fieldToMatch = fieldToMatch
    this.textTransformations = textTransformations
    this.capacity = capacity

  }
  static new(name: string, capacity: number, patterns: string[], fieldToMatch: any, textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[] = [{ priority: 0, type: "NONE" }]): RegexPatter {
    return new RegexPatter(name, capacity, patterns, fieldToMatch, textTransformations)
  }
}

export class WafrStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    let regularExpressions: RegexPatter[] = [
      RegexPatter.new("DirectoryTraversal", 35, RegexPatter.directoryTraversal, RegexPatter.MatchAllQueryArguments),
      RegexPatter.new("DisallowHtmlInForms", 25, RegexPatter.allHtmlTags, RegexPatter.MatchBodyMatchOversize),
      RegexPatter.new("PhpSystem", 35, RegexPatter.phpSystem, RegexPatter.MatchAllQueryArguments),
      RegexPatter.new("PostEscapeCommand", 25, RegexPatter.commands, RegexPatter.MatchBodyNoMatchOversize),
      RegexPatter.new("XmlHtmlAllTags", 35, RegexPatter.allHtmlTags, RegexPatter.MatchAllQueryArguments), //need to add xml
    ]
    for (let x of regularExpressions) {
      let regex = new wafv2.CfnRegexPatternSet(this, `RuleSet${x.name}`, {
        scope: "REGIONAL",
        name: x.name,
        regularExpressionList: x.patterns
      })
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
            statement: {
              regexPatternSetReferenceStatement: {
                arn: regex.attrArn,
                fieldToMatch: x.fieldToMatch,
                textTransformations: x.textTransformations
              }
            }
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
