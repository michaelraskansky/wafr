import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
export class RuleGroup {
    public name: string;
    public patterns: string[];
    public capacity: number;
    public statment: wafv2.CfnRuleGroup.StatementProperty
    public fieldToMatch: wafv2.CfnRuleGroup.FieldToMatchProperty;
    public textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[];

    // Matchers
    public static MatchAllQueryArguments = { allQueryArguments: {} }
    public static MatchQueryString = { queryString: {} }
    public static MatchBodyNoMatchOversize = { body: { oversizeHandling: "NO_MATCH" } }


    // Transformations
    constructor(name: string, capacity: number, statment: wafv2.CfnRuleGroup.StatementProperty) {
        this.name = name;
        this.statment = statment
        this.capacity = capacity
    }
}
export class RuleGroups {
    public static ruleGroups(regexMap: { [key: string]: string; }) {
        return [
            new RuleGroup("DirectoryTraversal", 25, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["DirectoryTraversal"],
                    fieldToMatch: RuleGroup.MatchQueryString,
                    textTransformations: [
                        { priority: 0, type: "NONE" }
                    ]
                }
            }),
            new RuleGroup("ForbiddenCommandsBody", 100, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["Commands"],
                    fieldToMatch: {
                        body: {
                            oversizeHandling: "MATCH"
                        }
                    },
                    textTransformations: [
                        { priority: 0, type: "URL_DECODE" },
                        { priority: 1, type: "CMD_LINE" }
                    ]
                }
            }),

            new RuleGroup("PostEscapeCommand", 60, {
                andStatement: {
                    statements: [
                        {
                            regexPatternSetReferenceStatement: {
                                arn: regexMap["CommandAppender"],
                                fieldToMatch: {
                                    body: {
                                        oversizeHandling: "MATCH"
                                    }
                                },
                                textTransformations: [
                                    { priority: 0, type: "NONE" }

                                ]
                            }
                        },
                        {
                            regexPatternSetReferenceStatement: {
                                arn: regexMap["Commands"],
                                fieldToMatch: {
                                    body: {
                                        oversizeHandling: "MATCH"
                                    }
                                },
                                textTransformations: [
                                    { priority: 0, type: "CMD_LINE" }
                                ]
                            }
                        }
                    ]
                }
            }),

            new RuleGroup("PhpSystem", 35, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["PhpSystem"],
                    fieldToMatch: RuleGroup.MatchAllQueryArguments,
                    textTransformations: [
                        { priority: 0, type: "NONE" }
                    ]
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
                                fieldToMatch: { body: { oversizeHandling: "MATCH" } },
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
        ]
    }
}