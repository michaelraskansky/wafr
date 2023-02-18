import * as wafv2 from 'aws-cdk-lib/aws-wafv2';
export class RuleGroup {
    public name: string;
    public patterns: string[];
    public capacity: number;
    public statment: wafv2.CfnRuleGroup.StatementProperty
    public fieldToMatch: wafv2.CfnRuleGroup.FieldToMatchProperty;
    public textTransformations: wafv2.CfnRuleGroup.TextTransformationProperty[];

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

            // Block html tags 
            new RuleGroup("BlockHtmlTags", 55, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["HtmlTags"],
                    fieldToMatch: {
                        body: {
                            oversizeHandling: "NO_MATCH"
                        }
                    },
                    textTransformations: [
                        { priority: 0, type: "URL_DECODE_UNI" },
                        { priority: 1, type: "HTML_ENTITY_DECODE" },
                        { priority: 2, type: "LOWERCASE" },
                    ]
                }
            }),

            // Block directory traversal
            new RuleGroup("DirectoryTraversal", 25, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["DirectoryTraversal"],
                    fieldToMatch: {
                        queryString: {

                        }
                    },
                    textTransformations: [
                        { priority: 0, type: "NONE" }
                    ]
                }
            }),

            // Block commands
            new RuleGroup("PostEscapeCommand", 45, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["Commands"],
                    fieldToMatch: {
                        body: {
                            oversizeHandling: "MATCH"
                        }
                    },
                    textTransformations: [
                        { priority: 0, type: "URL_DECODE_UNI" },
                        { priority: 1, type: "CMD_LINE" }
                    ]
                }
            }),

            // Block PHP  system commans
            new RuleGroup("PhpSystem", 35, {
                regexPatternSetReferenceStatement: {
                    arn: regexMap["PhpSystem"],
                    fieldToMatch: { allQueryArguments: {} },
                    textTransformations: [
                        { priority: 0, type: "NONE" }
                    ]
                }
            }),

            // Block SQL injection attacks high sensetivity
            new RuleGroup("SqliHighSensetivity", 110, {
                andStatement: {
                    statements: [
                        {
                            sqliMatchStatement: {
                                fieldToMatch: { allQueryArguments: {} },
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