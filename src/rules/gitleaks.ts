import type { RuleSet } from '../core/types.ts'

export const gitleaks: RuleSet = {
  "version": "v8.30.1",
  "rules": [
    {
      "id": "1password-secret-key",
      "pattern": "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
      "keywords": [
        "a3-"
      ],
      "secretGroup": 0,
      "entropy": 3.8,
      "allowlists": []
    },
    {
      "id": "1password-service-account-token",
      "pattern": "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
      "keywords": [
        "ops_"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "adafruit-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][dD][aA][fF][rR][uU][iI][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_\\-A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "adafruit"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "adobe-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][dD][oO][bB][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "adobe"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "adobe-client-secret",
      "pattern": "\\b(p8e-[a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "p8e-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "age-secret-key",
      "pattern": "AGE-SECRET-KEY-1[Q\\x50ZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
      "keywords": [
        "age-secret-key-1"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "airtable-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][iI][rR][tT][aA][bB][lL][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{17})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "airtable"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "airtable-personnal-access-token",
      "pattern": "\\b(pat[A-Za-z0-9]{14}\\.[a-f0-9]{64})\\b",
      "keywords": [
        "airtable"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "algolia-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][lL][gG][oO][lL][iI][aA])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "algolia"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "alibaba-access-key-id",
      "pattern": "\\b(LTAI[a-z0-9A-Z]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "ltai"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "alibaba-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][lL][iI][bB][aA][bB][aA])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{30})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "alibaba"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "anthropic-admin-api-key",
      "pattern": "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sk-ant-admin01"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "anthropic-api-key",
      "pattern": "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sk-ant-api03"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "artifactory-api-key",
      "pattern": "\\bAKCp[A-Za-z0-9]{69}\\b",
      "keywords": [
        "akcp"
      ],
      "secretGroup": 0,
      "entropy": 4.5,
      "allowlists": []
    },
    {
      "id": "artifactory-reference-token",
      "pattern": "\\bcmVmd[A-Za-z0-9]{59}\\b",
      "keywords": [
        "cmvmd"
      ],
      "secretGroup": 0,
      "entropy": 4.5,
      "allowlists": []
    },
    {
      "id": "asana-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][sS][aA][nN][aA])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "asana"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "asana-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][sS][aA][nN][aA])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "asana"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "atlassian-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:(?:ATLASSIAN|[Aa]tlassian)|(?:CONFLUENCE|[Cc]onfluence)|(?:JIRA|[Jj]ira))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{20}[a-f0-9A-F]{4})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)|\\b([Aa][Tt][Aa][Tt][Tt]3[A-Za-z0-9_\\-=a-zA-Z]{186})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "atlassian",
        "confluence",
        "jira",
        "atatt3"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "authress-service-client-access-key",
      "pattern": "\\b((?:sc|ext|scauth|authress)_[a-z0-9A-Z]{5,30}\\.[a-z0-9A-Z]{4,6}\\.(?:acc)[_\\-][a-z0-9\\-A-Z]{10,32}\\.[a-z0-9+/_=\\-A-Z]{30,120})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sc_",
        "ext_",
        "scauth_",
        "authress_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "aws-access-token",
      "pattern": "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
      "keywords": [
        "a3t",
        "akia",
        "asia",
        "abia",
        "acca"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": [
        {
          "patterns": [
            "[^\\n]+EXAMPLE$"
          ],
          "stopwords": [],
          "target": "secret"
        }
      ]
    },
    {
      "id": "aws-amazon-bedrock-api-key-long-lived",
      "pattern": "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "absk"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "aws-amazon-bedrock-api-key-short-lived",
      "pattern": "b\\x65drock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
      "keywords": [
        "bedrock-api-key-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "azure-ad-client-secret",
      "pattern": "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.\\-]{31,34})(?:$|[\\\\'\"\\x60\\s<),])",
      "keywords": [
        "q~"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "beamer-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[bB][eE][aA][mM][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([bB]_[a-z0-9=_\\-A-Z]{44})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "beamer"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "bitbucket-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kK][eE][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "bitbucket"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "bitbucket-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[bB][iI][tT][bB][uU][cC][kK][eE][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "bitbucket"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "bittrex-access-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "bittrex"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "bittrex-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[bB][iI][tT][tT][rR][eE][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "bittrex"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "cisco-meraki-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[\\w.\\-]{0,50}?(?:(?:[Mm]eraki|MERAKI))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "meraki"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "clickhouse-cloud-api-secret-key",
      "pattern": "\\b(4b1d[A-Za-z0-9]{38})\\b",
      "keywords": [
        "4b1d"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "clojars-api-token",
      "pattern": "[Cc][Ll][Oo][Jj][Aa][Rr][Ss]_[a-z0-9A-Z]{60}",
      "keywords": [
        "clojars_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "cloudflare-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_\\-A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "cloudflare"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "cloudflare-global-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][lL][oO][uU][dD][fF][lL][aA][rR][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{37})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "cloudflare"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "cloudflare-origin-ca-key",
      "pattern": "\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "cloudflare",
        "v1.0-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "codecov-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][oO][dD][eE][cC][oO][vV])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "codecov"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "cohere-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[\\w.\\-]{0,50}?(?:[cC][oO][hH][eE][rR][eE]|[Cc][Oo]_[Aa][Pp][Ii]_[Kk][Ee][Yy])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "cohere",
        "co_api_key"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "coinbase-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][oO][iI][nN][bB][aA][sS][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_\\-A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "coinbase"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "confluent-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{16})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "confluent"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "confluent-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][oO][nN][fF][lL][uU][eE][nN][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "confluent"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "contentful-delivery-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[cC][oO][nN][tT][eE][nN][tT][fF][uU][lL])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{43})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "contentful"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "curl-auth-header",
      "pattern": "\\bcurl\\b(?:[^\\n]*?|[^\\n]*?(?:[\\r\\n]{1,2}[^\\n]*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sS][iI][cC][ \\t]([a-z0-9+/A-Z]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \\t]([\\w=~@.+/\\-]{8,})|([\\w=~@.+/\\-]{8,}))|(?:(?:[Xx]-(?:[a-zA-Z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \\t]{0,5}([\\w=~@.+/\\-]{8,}))\"|'(?:[Aa][uU][tT][hH][oO][rR][iI][zZ][aA][tT][iI][oO][nN]:[ \\t]{0,5}(?:[Bb][aA][sS][iI][cC][ \\t]([a-z0-9+/A-Z]{8,}={0,3})|(?:[Bb][eE][aA][rR][eE][rR]|(?:[Aa][pP][iI]-)?[Tt][oO][kK][eE][nN])[ \\t]([\\w=~@.+/\\-]{8,})|([\\w=~@.+/\\-]{8,}))|(?:(?:[Xx]-(?:[a-zA-Z]+-)?)?(?:[Aa][pP][iI]-?)?(?:[Kk][eE][yY]|[Tt][oO][kK][eE][nN])):[ \\t]{0,5}([\\w=~@.+/\\-]{8,}))')(?:\\B|\\s|$)",
      "keywords": [
        "curl"
      ],
      "secretGroup": 0,
      "entropy": 2.75,
      "allowlists": []
    },
    {
      "id": "curl-auth-user",
      "pattern": "\\bcurl\\b(?:[^\\n]*|[^\\n]*(?:[\\r\\n]{1,2}[^\\n]*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.\\-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.\\-]+)))(?:\\s|$)",
      "keywords": [
        "curl"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": [
        {
          "patterns": [
            "[^:]+:(?:change(?:it|me)|pass(?:word)?|pwd|test|token|\\*+|x+)",
            "['\"]?<[^>]+>['\"]?:['\"]?<[^>]+>|<[^:]+:[^>]+>['\"]?",
            "[^:]+:\\[[^]]+]",
            "['\"]?[^:]+['\"]?:['\"]?\\$(?:\\d|\\w+|\\{(?:\\d|\\w+)})['\"]?",
            "\\$\\([^)]+\\):\\$\\([^)]+\\)",
            "['\"]?\\$?{{[^}]+}}['\"]?:['\"]?\\$?{{[^}]+}}['\"]?"
          ],
          "stopwords": [],
          "target": "secret"
        }
      ]
    },
    {
      "id": "databricks-api-token",
      "pattern": "\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "dapi"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "datadog-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][aA][tT][aA][dD][oO][gG])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "datadog"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "defined-networking-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][nN][kK][eE][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([dD][nN][kK][eE][yY]-[a-z0-9=_\\-A-Z]{26}-[a-z0-9=_\\-A-Z]{52})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "dnkey"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "digitalocean-access-token",
      "pattern": "\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "doo_v1_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "digitalocean-pat",
      "pattern": "\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "dop_v1_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "digitalocean-refresh-token",
      "pattern": "\\b([dD][oO][rR]_[vV]1_[a-f0-9A-F]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "dor_v1_"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "discord-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "discord"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "discord-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{18})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "discord"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "discord-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][iI][sS][cC][oO][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "discord"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "doppler-api-token",
      "pattern": "dp\\.pt\\.[a-z0-9A-Z]{43}",
      "keywords": [
        "dp.pt."
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "droneci-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][rR][oO][nN][eE][cC][iI])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "droneci"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "dropbox-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{15})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "dropbox"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "dropbox-long-lived-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{11}([Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa][Aa])[a-z0-9\\-_=A-Z]{43})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "dropbox"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "dropbox-short-lived-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[dD][rR][oO][pP][bB][oO][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([sS][lL]\\.[a-z0-9\\-=_A-Z]{135})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "dropbox"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "duffel-api-token",
      "pattern": "duffel_(?:test|live)_[a-z0-9_\\-=A-Z]{43}",
      "keywords": [
        "duffel_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "dynatrace-api-token",
      "pattern": "dt0c01\\.[a-z0-9A-Z]{24}\\.[a-z0-9A-Z]{64}",
      "keywords": [
        "dt0c01."
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "easypost-api-token",
      "pattern": "\\bEZAK[a-z0-9A-Z]{54}\\b",
      "keywords": [
        "ezak"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "easypost-test-api-token",
      "pattern": "\\bEZTK[a-z0-9A-Z]{54}\\b",
      "keywords": [
        "eztk"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "etsy-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:(?:ETSY|[Ee]tsy))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{24})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "etsy"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "facebook-access-token",
      "pattern": "\\b(\\d{15,16}(\\||%)[0-9a-z\\-_A-Z]{27,40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "facebook"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "facebook-page-access-token",
      "pattern": "\\b(EAA[MC][a-z0-9A-Z]{100,})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "eaam",
        "eaac"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "facebook-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][aA][cC][eE][bB][oO][oO][kK])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "facebook"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "fastly-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][aA][sS][tT][lL][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "fastly"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "finicity-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "finicity"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "finicity-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][iI][nN][iI][cC][iI][tT][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{20})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "finicity"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "finnhub-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][iI][nN][nN][hH][uU][bB])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{20})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "finnhub"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "flickr-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][lL][iI][cC][kK][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "flickr"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "flutterwave-encryption-key",
      "pattern": "FLWSECK_TEST-[a-h0-9A-H]{12}",
      "keywords": [
        "flwseck_test"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "flutterwave-public-key",
      "pattern": "FLWPUBK_TEST-[a-h0-9A-H]{32}-[Xx]",
      "keywords": [
        "flwpubk_test"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "flutterwave-secret-key",
      "pattern": "FLWSECK_TEST-[a-h0-9A-H]{32}-[Xx]",
      "keywords": [
        "flwseck_test"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "flyio-access-token",
      "pattern": "\\b((?:fo1_[\\w\\-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "fo1_",
        "fm1",
        "fm2_"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "frameio-api-token",
      "pattern": "fio-u-[a-z0-9\\-_=A-Z]{64}",
      "keywords": [
        "fio-u-"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "freshbooks-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[fF][rR][eE][sS][hH][bB][oO][oO][kK][sS])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "freshbooks"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "gcp-api-key",
      "pattern": "\\b(AIza[\\w\\-]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "aiza"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": [
        {
          "patterns": [
            "A\\x49zaSyabcdefghijklmnopqrstuvwxyz1234567",
            "A\\x49zaSyAnLA7NfeLquW1tJFpx_eQCxoX-oo6YyIs",
            "A\\x49zaSyCkEhVjf3pduRDt6d1yKOMitrUEke8agEM",
            "A\\x49zaSyDMAScliyLx7F0NPDEJi1QmyCgHIAODrlU",
            "A\\x49zaSyD3asb-2pEZVqMkmL6M9N6nHZRR_znhrh0",
            "A\\x49zayDNSXIbFmlXbIE6mCzDLQAqITYefhixbX4A",
            "A\\x49zaSyAdOS2zB6NCsk1pCdZ4-P6GBdi_UUPwX7c",
            "A\\x49zaSyASWm6HmTMdYWpgMnjRBjxcQ9CKctWmLd4",
            "A\\x49zaSyANUvH9H9BsUccjsu2pCmEkOPjjaXeDQgY",
            "A\\x49zaSyA5_iVawFQ8ABuTZNUdcwERLJv_a_p4wtM",
            "A\\x49zaSyA4UrcGxgwQFTfaI3no3t7Lt1sjmdnP5sQ",
            "A\\x49zaSyDSb51JiIcB6OJpwwMicseKRhhrOq1cS7g",
            "A\\x49zaSyBF2RrAIm4a0mO64EShQfqfd2AFnzAvvuU",
            "A\\x49zaSyBcE-OOIbhjyR83gm4r2MFCu4MJmprNXsw",
            "A\\x49zaSyB8qGxt4ec15vitgn44duC5ucxaOi4FmqE",
            "A\\x49zaSyA8vmApnrHNFE0bApF4hoZ11srVL_n0nvY"
          ],
          "stopwords": [],
          "target": "secret"
        }
      ]
    },
    {
      "id": "generic-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[aA][cC][cC][eE][sS][sS]|[aA][uU][tT][hH]|(?:[Aa]pi|API)|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL]|[cC][rR][eE][dD][sS]|[kK][eE][yY]|[pP][aA][sS][sS][wW](?:[oO][rR])?[dD]|[sS][eE][cC][rR][eE][tT]|[tT][oO][kK][eE][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([\\w.=\\-]{10,150}|[a-z0-9A-Z][a-z0-9+/A-Z]{11,}={0,3})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "access",
        "api",
        "auth",
        "key",
        "credential",
        "creds",
        "passwd",
        "password",
        "secret",
        "token"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": [
        {
          "patterns": [
            "^[a-zA-Z_.\\-]+$"
          ],
          "stopwords": [],
          "target": "secret"
        },
        {
          "patterns": [
            "(?:[aA][cC][cC][eE][sS][sS](?:[iI][bB][iI][lL][iI][tT][yY]|[oO][rR])|[aA][cC][cC][eE][sS][sS][_.\\-]?[iI][dD]|[rR][aA][nN][dD][oO][mM][_.\\-]?[aA][cC][cC][eE][sS][sS]|[aA][pP][iI][_.\\-]?(?:[iI][dD]|[nN][aA][mM][eE]|[vV][eE][rR][sS][iI][oO][nN])|[rR][aA][pP][iI][dD]|[cC][aA][pP][iI][tT][aA][lL]|[a-z0-9\\-A-Z]*?[aA][pP][iI][a-z0-9\\-A-Z]*?:[jJ][aA][rR]:|[aA][uU][tT][hH][oO][rR]|[Xx]-[Mm][Ss]-[Ee][xX][cC][hH][aA][nN][gG][eE]-[Oo][rR][gG][aA][nN][iI][zZ][aA][tT][iI][oO][nN]-[Aa][uU][tT][hH]|[Aa][uU][tT][hH][eE][nN][tT][iI][cC][aA][tT][iI][oO][nN]-[Rr][eE][sS][uU][lL][tT][sS]|(?:[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]?[_.\\-]?[iI][dD]|[wW][iI][tT][hH][Cc][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS])|(?:[bB][uU][cC][kK][eE][tT]|[fF][oO][rR][eE][iI][gG][nN]|[hH][oO][tT]|[iI][dD][xX]|[nN][aA][tT][uU][rR][aA][lL]|[pP][rR][iI][mM][aA][rR][yY]|[pP][uU][bB](?:[lL][iI][cC])?|[sS][cC][hH][eE][mM][aA]|[sS][eE][qQ][uU][eE][nN][cC][eE])[_.\\-]?[kK][eE][yY]|(?:[tT][uU][rR][kK][eE][yY])|[kK][eE][yY][_.\\-]?(?:[aA][lL][iI][aA][sS]|[bB][oO][aA][rR][dD]|[cC][oO][dD][eE]|[fF][rR][aA][mM][eE]|[iI][dD]|[lL][eE][nN][gG][tT][hH]|[mM][eE][sS][hH]|[nN][aA][mM][eE]|[pP][aA][iI][rR]|[pP][rR][eE][sS][sS](?:[eE][dD])?|[rR][iI][nN][gG]|[sS][eE][lL][eE][cC][tT][oO][rR]|[sS][iI][gG][nN][aA][tT][uU][rR][eE]|[sS][iI][zZ][eE]|[sS][tT][oO][nN][eE]|[sS][tT][oO][rR][eE][tT][yY][pP][eE]|[wW][oO][rR][dD]|[uU][pP]|[dD][oO][wW][nN]|[lL][eE][fF][tT]|[rR][iI][gG][hH][tT])|[kK][eE][yY][_.\\-]?[vV][aA][uU][lL][tT][_.\\-]?(?:[iI][dD]|[nN][aA][mM][eE])|[kK][eE][yY][Vv][aA][uU][lL][tT][Tt][oO][Ss][tT][oO][rR][eE][Ss][eE][cC][rR][eE][tT][sS]|[kK][eE][yY](?:[sS][tT][oO][rR][eE]|[tT][aA][bB])[_.\\-]?(?:[fF][iI][lL][eE]|[pP][aA][tT][hH])|[iI][sS][sS][uU][eE][rR][kK][eE][yY][hH][aA][sS][hH]|(?:[DdMm]onkey|[DM]ONKEY)|[kK][eE][yY][iI][nN][gG]|(?:[sS][eE][cC][rR][eE][tT])[_.\\-]?(?:[lL][eE][nN][gG][tT][hH]|[nN][aA][mM][eE]|[sS][iI][zZ][eE])|[Uu][sS][eE][rR][Ss][eE][cC][rR][eE][tT][sS][Ii][dD]|(?:[cC][sS][rR][fF])[_.\\-]?[tT][oO][kK][eE][nN]|(?:[iI][oO]\\.[jJ][sS][oO][nN][wW][eE][bB][tT][oO][kK][eE][nN][ \\t]?:[ \\t]?[\\w\\-]+)|(?:[aA][pP][iI]|[cC][rR][eE][dD][eE][nN][tT][iI][aA][lL][sS]|[tT][oO][kK][eE][nN])[_.\\-]?(?:[eE][nN][dD][pP][oO][iI][nN][tT]|[uU][rR][ilIL])|[pP][uU][bB][lL][iI][cC][_.\\-]?[tT][oO][kK][eE][nN]|(?:[kK][eE][yY]|[tT][oO][kK][eE][nN])[_.\\-]?[fF][iI][lL][eE]|(?:(?:[A-Z_]+=\\n[A-Z_]+=|[a-z_]+=\\n[a-z_]+=)(?:\\n|$))|(?:(?:[A-Z.]+=\\n[A-Z.]+=|[a-z.]+=\\n[a-z.]+=)(?:\\n|$)))"
          ],
          "stopwords": [
            "000000",
            "6fe4476ee5a1832882e326b506d14126",
            "_ec2_",
            "aaaaaa",
            "about",
            "abstract",
            "academy",
            "acces",
            "account",
            "act-",
            "act.",
            "act_",
            "action",
            "active",
            "actively",
            "activity",
            "adapter",
            "add-",
            "add-on",
            "add.",
            "add_",
            "addon",
            "addres",
            "admin",
            "adobe",
            "advanced",
            "adventure",
            "agent",
            "agile",
            "air-",
            "air.",
            "air_",
            "ajax",
            "akka",
            "alert",
            "alfred",
            "algorithm",
            "all-",
            "all.",
            "all_",
            "alloy",
            "alpha",
            "amazon",
            "amqp",
            "analysi",
            "analytic",
            "analyzer",
            "android",
            "angular",
            "angularj",
            "animate",
            "animation",
            "another",
            "ansible",
            "answer",
            "ant-",
            "ant.",
            "ant_",
            "any-",
            "any.",
            "any_",
            "apache",
            "app-",
            "app.",
            "app_",
            "apple",
            "arch",
            "archive",
            "archived",
            "arduino",
            "array",
            "art-",
            "art.",
            "art_",
            "article",
            "asp-",
            "asp.",
            "asp_",
            "asset",
            "async",
            "atom",
            "attention",
            "audio",
            "audit",
            "aura",
            "auth",
            "author",
            "authorize",
            "auto",
            "automated",
            "automatic",
            "awesome",
            "aws_",
            "azure",
            "back",
            "backbone",
            "backend",
            "backup",
            "bar-",
            "bar.",
            "bar_",
            "base",
            "based",
            "bash",
            "basic",
            "batch",
            "been",
            "beer",
            "behavior",
            "being",
            "benchmark",
            "best",
            "beta",
            "better",
            "big-",
            "big.",
            "big_",
            "binary",
            "binding",
            "bit-",
            "bit.",
            "bit_",
            "bitcoin",
            "block",
            "blog",
            "board",
            "book",
            "bookmark",
            "boost",
            "boot",
            "bootstrap",
            "bosh",
            "bot-",
            "bot.",
            "bot_",
            "bower",
            "box-",
            "box.",
            "box_",
            "boxen",
            "bracket",
            "branch",
            "bridge",
            "browser",
            "brunch",
            "buffer",
            "bug-",
            "bug.",
            "bug_",
            "build",
            "builder",
            "building",
            "buildout",
            "buildpack",
            "built",
            "bundle",
            "busines",
            "but-",
            "but.",
            "but_",
            "button",
            "cache",
            "caching",
            "cakephp",
            "calendar",
            "call",
            "camera",
            "campfire",
            "can-",
            "can.",
            "can_",
            "canva",
            "captcha",
            "capture",
            "card",
            "carousel",
            "case",
            "cassandra",
            "cat-",
            "cat.",
            "cat_",
            "category",
            "center",
            "cento",
            "challenge",
            "change",
            "changelog",
            "channel",
            "chart",
            "chat",
            "cheat",
            "check",
            "checker",
            "chef",
            "ches",
            "chinese",
            "chosen",
            "chrome",
            "ckeditor",
            "clas",
            "classe",
            "classic",
            "clean",
            "cli-",
            "cli.",
            "cli_",
            "client",
            "clojure",
            "clone",
            "closure",
            "cloud",
            "club",
            "cluster",
            "cms-",
            "cms_",
            "coco",
            "code",
            "coding",
            "coffee",
            "color",
            "combination",
            "combo",
            "command",
            "commander",
            "comment",
            "commit",
            "common",
            "community",
            "compas",
            "compiler",
            "complete",
            "component",
            "composer",
            "computer",
            "computing",
            "con-",
            "con.",
            "con_",
            "concept",
            "conf",
            "config",
            "connect",
            "connector",
            "console",
            "contact",
            "container",
            "contao",
            "content",
            "contest",
            "context",
            "control",
            "convert",
            "converter",
            "conway'",
            "cookbook",
            "cookie",
            "cool",
            "copy",
            "cordova",
            "core",
            "couchbase",
            "couchdb",
            "countdown",
            "counter",
            "course",
            "craft",
            "crawler",
            "create",
            "creating",
            "creator",
            "credential",
            "crm-",
            "crm.",
            "crm_",
            "cros",
            "crud",
            "csv-",
            "csv.",
            "csv_",
            "cube",
            "cucumber",
            "cuda",
            "current",
            "currently",
            "custom",
            "daemon",
            "dark",
            "dart",
            "dash",
            "dashboard",
            "data",
            "database",
            "date",
            "day-",
            "day.",
            "day_",
            "dead",
            "debian",
            "debug",
            "debugger",
            "deck",
            "define",
            "del-",
            "del.",
            "del_",
            "delete",
            "demo",
            "deploy",
            "design",
            "designer",
            "desktop",
            "detection",
            "detector",
            "dev-",
            "dev.",
            "dev_",
            "develop",
            "developer",
            "device",
            "devise",
            "diff",
            "digital",
            "directive",
            "directory",
            "discovery",
            "display",
            "django",
            "dns-",
            "dns_",
            "doc-",
            "doc.",
            "doc_",
            "docker",
            "docpad",
            "doctrine",
            "document",
            "doe-",
            "doe.",
            "doe_",
            "dojo",
            "dom-",
            "dom.",
            "dom_",
            "domain",
            "don't",
            "done",
            "dot-",
            "dot.",
            "dot_",
            "dotfile",
            "download",
            "draft",
            "drag",
            "drill",
            "drive",
            "driven",
            "driver",
            "drop",
            "dropbox",
            "drupal",
            "dsl-",
            "dsl.",
            "dsl_",
            "dynamic",
            "easy",
            "ecdsa",
            "eclipse",
            "edit",
            "editing",
            "edition",
            "editor",
            "element",
            "emac",
            "email",
            "embed",
            "embedded",
            "ember",
            "emitter",
            "emulator",
            "encoding",
            "endpoint",
            "engine",
            "english",
            "enhanced",
            "entity",
            "entry",
            "env_",
            "episode",
            "erlang",
            "error",
            "espresso",
            "event",
            "evented",
            "example",
            "exchange",
            "exercise",
            "experiment",
            "expire",
            "exploit",
            "explorer",
            "export",
            "exporter",
            "expres",
            "ext-",
            "ext.",
            "ext_",
            "extended",
            "extension",
            "external",
            "extra",
            "extractor",
            "fabric",
            "facebook",
            "factory",
            "fake",
            "fast",
            "feature",
            "feed",
            "fewfwef",
            "ffmpeg",
            "field",
            "file",
            "filter",
            "find",
            "finder",
            "firefox",
            "firmware",
            "first",
            "fish",
            "fix-",
            "fix_",
            "flash",
            "flask",
            "flat",
            "flex",
            "flexible",
            "flickr",
            "flow",
            "fluent",
            "fluentd",
            "fluid",
            "folder",
            "font",
            "force",
            "foreman",
            "fork",
            "form",
            "format",
            "formatter",
            "forum",
            "foundry",
            "framework",
            "free",
            "friend",
            "friendly",
            "front-end",
            "frontend",
            "ftp-",
            "ftp.",
            "ftp_",
            "fuel",
            "full",
            "fun-",
            "fun.",
            "fun_",
            "func",
            "future",
            "gaia",
            "gallery",
            "game",
            "gateway",
            "gem-",
            "gem.",
            "gem_",
            "gen-",
            "gen.",
            "gen_",
            "general",
            "generator",
            "generic",
            "genetic",
            "get-",
            "get.",
            "get_",
            "getenv",
            "getting",
            "ghost",
            "gist",
            "git-",
            "git.",
            "git_",
            "github",
            "gitignore",
            "gitlab",
            "glas",
            "gmail",
            "gnome",
            "gnu-",
            "gnu.",
            "gnu_",
            "goal",
            "golang",
            "gollum",
            "good",
            "google",
            "gpu-",
            "gpu.",
            "gpu_",
            "gradle",
            "grail",
            "graph",
            "graphic",
            "great",
            "grid",
            "groovy",
            "group",
            "grunt",
            "guard",
            "gui-",
            "gui.",
            "gui_",
            "guide",
            "guideline",
            "gulp",
            "gwt-",
            "gwt.",
            "gwt_",
            "hack",
            "hackathon",
            "hacker",
            "hacking",
            "hadoop",
            "haml",
            "handler",
            "hardware",
            "has-",
            "has_",
            "hash",
            "haskell",
            "have",
            "haxe",
            "hello",
            "help",
            "helper",
            "here",
            "hero",
            "heroku",
            "high",
            "hipchat",
            "history",
            "home",
            "homebrew",
            "homepage",
            "hook",
            "host",
            "hosting",
            "hot-",
            "hot.",
            "hot_",
            "house",
            "how-",
            "how.",
            "how_",
            "html",
            "http",
            "hub-",
            "hub.",
            "hub_",
            "hubot",
            "human",
            "icon",
            "ide-",
            "ide.",
            "ide_",
            "idea",
            "identity",
            "idiomatic",
            "image",
            "impact",
            "import",
            "important",
            "importer",
            "impres",
            "index",
            "infinite",
            "info",
            "injection",
            "inline",
            "input",
            "inside",
            "inspector",
            "instagram",
            "install",
            "installer",
            "instant",
            "intellij",
            "interface",
            "internet",
            "interview",
            "into",
            "intro",
            "ionic",
            "iphone",
            "ipython",
            "irc-",
            "irc_",
            "iso-",
            "iso.",
            "iso_",
            "issue",
            "jade",
            "jasmine",
            "java",
            "jbos",
            "jekyll",
            "jenkin",
            "jetbrains",
            "job-",
            "job.",
            "job_",
            "joomla",
            "jpa-",
            "jpa.",
            "jpa_",
            "jquery",
            "json",
            "just",
            "kafka",
            "karma",
            "kata",
            "kernel",
            "keyboard",
            "kindle",
            "kit-",
            "kit.",
            "kit_",
            "kitchen",
            "knife",
            "koan",
            "kohana",
            "lab-",
            "lab.",
            "lab_",
            "lambda",
            "lamp",
            "language",
            "laravel",
            "last",
            "latest",
            "latex",
            "launcher",
            "layer",
            "layout",
            "lazy",
            "ldap",
            "leaflet",
            "league",
            "learn",
            "learning",
            "led-",
            "led.",
            "led_",
            "leetcode",
            "les-",
            "les.",
            "les_",
            "level",
            "leveldb",
            "lib-",
            "lib.",
            "lib_",
            "librarie",
            "library",
            "license",
            "life",
            "liferay",
            "light",
            "lightbox",
            "like",
            "line",
            "link",
            "linked",
            "linkedin",
            "linux",
            "lisp",
            "list",
            "lite",
            "little",
            "load",
            "loader",
            "local",
            "location",
            "lock",
            "log-",
            "log.",
            "log_",
            "logger",
            "logging",
            "logic",
            "login",
            "logstash",
            "longer",
            "look",
            "love",
            "lua-",
            "lua.",
            "lua_",
            "mac-",
            "mac.",
            "mac_",
            "machine",
            "made",
            "magento",
            "magic",
            "mail",
            "make",
            "maker",
            "making",
            "man-",
            "man.",
            "man_",
            "manage",
            "manager",
            "manifest",
            "manual",
            "map-",
            "map.",
            "map_",
            "mapper",
            "mapping",
            "markdown",
            "markup",
            "master",
            "math",
            "matrix",
            "maven",
            "md5",
            "mean",
            "media",
            "mediawiki",
            "meetup",
            "memcached",
            "memory",
            "menu",
            "merchant",
            "message",
            "messaging",
            "meta",
            "metadata",
            "meteor",
            "method",
            "metric",
            "micro",
            "middleman",
            "migration",
            "minecraft",
            "miner",
            "mini",
            "minimal",
            "mirror",
            "mit-",
            "mit.",
            "mit_",
            "mobile",
            "mocha",
            "mock",
            "mod-",
            "mod.",
            "mod_",
            "mode",
            "model",
            "modern",
            "modular",
            "module",
            "modx",
            "money",
            "mongo",
            "mongodb",
            "mongoid",
            "mongoose",
            "monitor",
            "monkey",
            "more",
            "motion",
            "moved",
            "movie",
            "mozilla",
            "mqtt",
            "mule",
            "multi",
            "multiple",
            "music",
            "mustache",
            "mvc-",
            "mvc.",
            "mvc_",
            "mysql",
            "nagio",
            "name",
            "native",
            "need",
            "neo-",
            "neo.",
            "neo_",
            "nest",
            "nested",
            "net-",
            "net.",
            "net_",
            "nette",
            "network",
            "new-",
            "new.",
            "new_",
            "next",
            "nginx",
            "ninja",
            "nlp-",
            "nlp.",
            "nlp_",
            "node",
            "nodej",
            "nosql",
            "not-",
            "not.",
            "not_",
            "note",
            "notebook",
            "notepad",
            "notice",
            "notifier",
            "now-",
            "now.",
            "now_",
            "number",
            "oauth",
            "object",
            "objective",
            "obsolete",
            "ocaml",
            "octopres",
            "official",
            "old-",
            "old.",
            "old_",
            "onboard",
            "online",
            "only",
            "open",
            "opencv",
            "opengl",
            "openshift",
            "openwrt",
            "option",
            "oracle",
            "org-",
            "org.",
            "org_",
            "origin",
            "original",
            "orm-",
            "orm.",
            "orm_",
            "osx-",
            "osx_",
            "our-",
            "our.",
            "our_",
            "out-",
            "out.",
            "out_",
            "output",
            "over",
            "overview",
            "own-",
            "own.",
            "own_",
            "pack",
            "package",
            "packet",
            "page",
            "panel",
            "paper",
            "paperclip",
            "para",
            "parallax",
            "parallel",
            "parse",
            "parser",
            "parsing",
            "particle",
            "party",
            "password",
            "patch",
            "path",
            "pattern",
            "payment",
            "paypal",
            "pdf-",
            "pdf.",
            "pdf_",
            "pebble",
            "people",
            "perl",
            "personal",
            "phalcon",
            "phoenix",
            "phone",
            "phonegap",
            "photo",
            "php-",
            "php.",
            "php_",
            "physic",
            "picker",
            "pipeline",
            "platform",
            "play",
            "player",
            "please",
            "plu-",
            "plu.",
            "plu_",
            "plug-in",
            "plugin",
            "plupload",
            "png-",
            "png.",
            "png_",
            "poker",
            "polyfill",
            "polymer",
            "pool",
            "pop-",
            "pop.",
            "pop_",
            "popcorn",
            "popup",
            "port",
            "portable",
            "portal",
            "portfolio",
            "post",
            "power",
            "powered",
            "powerful",
            "prelude",
            "pretty",
            "preview",
            "principle",
            "print",
            "pro-",
            "pro.",
            "pro_",
            "problem",
            "proc",
            "product",
            "profile",
            "profiler",
            "program",
            "progres",
            "project",
            "protocol",
            "prototype",
            "provider",
            "proxy",
            "public",
            "pull",
            "puppet",
            "pure",
            "purpose",
            "push",
            "pusher",
            "pyramid",
            "python",
            "quality",
            "query",
            "queue",
            "quick",
            "rabbitmq",
            "rack",
            "radio",
            "rail",
            "railscast",
            "random",
            "range",
            "raspberry",
            "rdf-",
            "rdf.",
            "rdf_",
            "react",
            "reactive",
            "read",
            "reader",
            "readme",
            "ready",
            "real",
            "real-time",
            "reality",
            "realtime",
            "recipe",
            "recorder",
            "red-",
            "red.",
            "red_",
            "reddit",
            "redi",
            "redmine",
            "reference",
            "refinery",
            "refresh",
            "registry",
            "related",
            "release",
            "remote",
            "rendering",
            "repo",
            "report",
            "request",
            "require",
            "required",
            "requirej",
            "research",
            "resource",
            "response",
            "resque",
            "rest",
            "restful",
            "resume",
            "reveal",
            "reverse",
            "review",
            "riak",
            "rich",
            "right",
            "ring",
            "robot",
            "role",
            "room",
            "router",
            "routing",
            "rpc-",
            "rpc.",
            "rpc_",
            "rpg-",
            "rpg.",
            "rpg_",
            "rspec",
            "ruby-",
            "ruby.",
            "ruby_",
            "rule",
            "run-",
            "run.",
            "run_",
            "runner",
            "running",
            "runtime",
            "rust",
            "rvm-",
            "rvm.",
            "rvm_",
            "salt",
            "sample",
            "sandbox",
            "sas-",
            "sas.",
            "sas_",
            "sbt-",
            "sbt.",
            "sbt_",
            "scala",
            "scalable",
            "scanner",
            "schema",
            "scheme",
            "school",
            "science",
            "scraper",
            "scratch",
            "screen",
            "script",
            "scroll",
            "scs-",
            "scs.",
            "scs_",
            "sdk-",
            "sdk.",
            "sdk_",
            "sdl-",
            "sdl.",
            "sdl_",
            "search",
            "secure",
            "security",
            "see-",
            "see.",
            "see_",
            "seed",
            "select",
            "selector",
            "selenium",
            "semantic",
            "sencha",
            "send",
            "sentiment",
            "serie",
            "server",
            "service",
            "session",
            "set-",
            "set.",
            "set_",
            "setting",
            "setup",
            "sha1",
            "sha2",
            "sha256",
            "share",
            "shared",
            "sharing",
            "sheet",
            "shell",
            "shield",
            "shipping",
            "shop",
            "shopify",
            "shortener",
            "should",
            "show",
            "showcase",
            "side",
            "silex",
            "simple",
            "simulator",
            "single",
            "site",
            "skeleton",
            "sketch",
            "skin",
            "slack",
            "slide",
            "slider",
            "slim",
            "small",
            "smart",
            "smtp",
            "snake",
            "snapshot",
            "snippet",
            "soap",
            "social",
            "socket",
            "software",
            "solarized",
            "solr",
            "solution",
            "solver",
            "some",
            "soon",
            "source",
            "space",
            "spark",
            "spatial",
            "spec",
            "sphinx",
            "spine",
            "spotify",
            "spree",
            "spring",
            "sprite",
            "sql-",
            "sql.",
            "sql_",
            "sqlite",
            "ssh-",
            "ssh.",
            "ssh_",
            "stack",
            "staging",
            "standard",
            "stanford",
            "start",
            "started",
            "starter",
            "startup",
            "stat",
            "statamic",
            "state",
            "static",
            "statistic",
            "statsd",
            "statu",
            "steam",
            "step",
            "still",
            "stm-",
            "stm.",
            "stm_",
            "storage",
            "store",
            "storm",
            "story",
            "strategy",
            "stream",
            "streaming",
            "string",
            "stripe",
            "structure",
            "studio",
            "study",
            "stuff",
            "style",
            "sublime",
            "sugar",
            "suite",
            "summary",
            "super",
            "support",
            "supported",
            "svg-",
            "svg.",
            "svg_",
            "svn-",
            "svn.",
            "svn_",
            "swagger",
            "swift",
            "switch",
            "switcher",
            "symfony",
            "symphony",
            "sync",
            "synopsi",
            "syntax",
            "system",
            "tab-",
            "tab.",
            "tab_",
            "table",
            "tag-",
            "tag.",
            "tag_",
            "talk",
            "target",
            "task",
            "tcp-",
            "tcp.",
            "tcp_",
            "tdd-",
            "tdd.",
            "tdd_",
            "team",
            "tech",
            "template",
            "term",
            "terminal",
            "testing",
            "tetri",
            "text",
            "textmate",
            "theme",
            "theory",
            "three",
            "thrift",
            "time",
            "timeline",
            "timer",
            "tiny",
            "tinymce",
            "tip-",
            "tip.",
            "tip_",
            "title",
            "todo",
            "todomvc",
            "token",
            "tool",
            "toolbox",
            "toolkit",
            "top-",
            "top.",
            "top_",
            "tornado",
            "touch",
            "tower",
            "tracker",
            "tracking",
            "traffic",
            "training",
            "transfer",
            "translate",
            "transport",
            "tree",
            "trello",
            "try-",
            "try.",
            "try_",
            "tumblr",
            "tut-",
            "tut.",
            "tut_",
            "tutorial",
            "tweet",
            "twig",
            "twitter",
            "type",
            "typo",
            "ubuntu",
            "uiview",
            "ultimate",
            "under",
            "unit",
            "unity",
            "universal",
            "unix",
            "update",
            "updated",
            "upgrade",
            "upload",
            "uploader",
            "uri-",
            "uri.",
            "uri_",
            "url-",
            "url.",
            "url_",
            "usage",
            "usb-",
            "usb.",
            "usb_",
            "use-",
            "use.",
            "use_",
            "used",
            "useful",
            "user",
            "using",
            "util",
            "utilitie",
            "utility",
            "vagrant",
            "validator",
            "value",
            "variou",
            "varnish",
            "version",
            "via-",
            "via.",
            "via_",
            "video",
            "view",
            "viewer",
            "vim-",
            "vim.",
            "vim_",
            "vimrc",
            "virtual",
            "vision",
            "visual",
            "vpn",
            "want",
            "warning",
            "watch",
            "watcher",
            "wave",
            "way-",
            "way.",
            "way_",
            "weather",
            "web-",
            "web_",
            "webapp",
            "webgl",
            "webhook",
            "webkit",
            "webrtc",
            "website",
            "websocket",
            "welcome",
            "what",
            "what'",
            "when",
            "where",
            "which",
            "why-",
            "why.",
            "why_",
            "widget",
            "wifi",
            "wiki",
            "win-",
            "win.",
            "win_",
            "window",
            "wip-",
            "wip.",
            "wip_",
            "within",
            "without",
            "wizard",
            "word",
            "wordpres",
            "work",
            "worker",
            "workflow",
            "working",
            "workshop",
            "world",
            "wrapper",
            "write",
            "writer",
            "writing",
            "written",
            "www-",
            "www.",
            "www_",
            "xamarin",
            "xcode",
            "xml-",
            "xml.",
            "xml_",
            "xmpp",
            "xxxxxx",
            "yahoo",
            "yaml",
            "yandex",
            "yeoman",
            "yet-",
            "yet.",
            "yet_",
            "yii-",
            "yii.",
            "yii_",
            "youtube",
            "yui-",
            "yui.",
            "yui_",
            "zend",
            "zero",
            "zip-",
            "zip.",
            "zip_",
            "zsh-",
            "zsh.",
            "zsh_"
          ],
          "target": "match"
        },
        {
          "patterns": [
            "--mount=type=secret,",
            "import[ \\t]+{[ \\t\\w,]+}[ \\t]+from[ \\t]+['\"][^'\"]+['\"]"
          ],
          "stopwords": [],
          "target": "line"
        }
      ]
    },
    {
      "id": "github-app-token",
      "pattern": "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
      "keywords": [
        "ghu_",
        "ghs_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "github-fine-grained-pat",
      "pattern": "github_pat_\\w{82}",
      "keywords": [
        "github_pat_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "github-oauth",
      "pattern": "gho_[0-9a-zA-Z]{36}",
      "keywords": [
        "gho_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "github-pat",
      "pattern": "ghp_[0-9a-zA-Z]{36}",
      "keywords": [
        "ghp_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "github-refresh-token",
      "pattern": "ghr_[0-9a-zA-Z]{36}",
      "keywords": [
        "ghr_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-cicd-job-token",
      "pattern": "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "glcbt-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-deploy-token",
      "pattern": "gldt-[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "gldt-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-feature-flag-client-token",
      "pattern": "glffct-[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "glffct-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-feed-token",
      "pattern": "glft-[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "glft-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-incoming-mail-token",
      "pattern": "glimt-[0-9a-zA-Z_\\-]{25}",
      "keywords": [
        "glimt-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-kubernetes-agent-token",
      "pattern": "glagent-[0-9a-zA-Z_\\-]{50}",
      "keywords": [
        "glagent-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-oauth-app-secret",
      "pattern": "gloas-[0-9a-zA-Z_\\-]{64}",
      "keywords": [
        "gloas-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-pat",
      "pattern": "glpat-[\\w\\-]{20}",
      "keywords": [
        "glpat-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-pat-routable",
      "pattern": "\\bglpat-[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "keywords": [
        "glpat-"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "gitlab-ptt",
      "pattern": "glptt-[0-9a-f]{40}",
      "keywords": [
        "glptt-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-rrt",
      "pattern": "GR1348941[\\w\\-]{20}",
      "keywords": [
        "gr1348941"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-runner-authentication-token",
      "pattern": "glrt-[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "glrt-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-runner-authentication-token-routable",
      "pattern": "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
      "keywords": [
        "glrt-"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "gitlab-scim-token",
      "pattern": "glsoat-[0-9a-zA-Z_\\-]{20}",
      "keywords": [
        "glsoat-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitlab-session-cookie",
      "pattern": "_gitlab_session=[0-9a-z]{32}",
      "keywords": [
        "_gitlab_session="
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "gitter-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[gG][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_\\-A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "gitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "gocardless-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[gG][oO][cC][aA][rR][dD][lL][eE][sS][sS])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([lL][iI][vV][eE]_[a-z0-9\\-_=A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "live_",
        "gocardless"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "grafana-api-key",
      "pattern": "\\b([eE][yY][Jj][rR][Ii][jJ][oO][iI][A-Za-z0-9a-zA-Z]{70,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "eyjrijoi"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "grafana-cloud-api-token",
      "pattern": "\\b([gG][lL][cC]_[A-Za-z0-9+/a-zA-Z]{32,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "glc_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "grafana-service-account-token",
      "pattern": "\\b([gG][lL][sS][aA]_[A-Za-z0-9a-zA-Z]{32}_[A-Fa-f0-9a-fA-F]{8})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "glsa_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "harness-api-key",
      "pattern": "(?:pat|sat)\\.[a-zA-Z0-9_\\-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
      "keywords": [
        "pat.",
        "sat."
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "hashicorp-tf-api-token",
      "pattern": "[a-z0-9A-Z]{14}\\.(?:atlasv1)\\.[a-z0-9\\-_=A-Z]{60,70}",
      "keywords": [
        "atlasv1"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "heroku-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[hH][eE][rR][oO][kK][uU])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "heroku"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "heroku-api-key-v2",
      "pattern": "\\b((HRKU-AA[0-9a-zA-Z_\\-]{58}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "hrku-aa"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "hubspot-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[hH][uU][bB][sS][pP][oO][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "hubspot"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "huggingface-access-token",
      "pattern": "\\b(hf_(?:[a-zA-Z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "hf_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "huggingface-organization-api-token",
      "pattern": "\\b(api_org_(?:[a-zA-Z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "api_org_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "infracost-api-token",
      "pattern": "\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "ico-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "intercom-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[iI][nN][tT][eE][rR][cC][oO][mM])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{60})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "intercom"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "intra42-client-secret",
      "pattern": "\\b(s-s4t2(?:ud|af)-[a\\x62cdef0123456789ABCDEF]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "intra",
        "s-s4t2ud-",
        "s-s4t2af-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "jfrog-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{73})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "jfrog-identity-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[jJ][fF][rR][oO][gG]|[aA][rR][tT][iI][fF][aA][cC][tT][oO][rR][yY]|[bB][iI][nN][tT][rR][aA][yY]|[xX][rR][aA][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "jfrog",
        "artifactory",
        "bintray",
        "xray"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "jwt",
      "pattern": "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_\\-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_\\-]{10,}={0,2})?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "ey"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "jwt-base64",
      "pattern": "\\bZXlK(?:(?<alg>aGJHY2lPaU)|(?<apu>aGNIVWlPaU)|(?<apv>aGNIWWlPaU)|(?<aud>aGRXUWlPaU)|(?<b64>aU5qUWlP)|(?<crit>amNtbDBJanBi)|(?<cty>amRIa2lPaU)|(?<epk>bGNHc2lPbn)|(?<enc>bGJtTWlPaU)|(?<jku>cWEzVWlPaU)|(?<jwk>cWQyc2lPb)|(?<iss>cGMzTWlPaU)|(?<iv>cGRpSTZJ)|(?<kid>cmFXUWlP)|(?<key_ops>clpYbGZiM0J6SWpwY)|(?<kty>cmRIa2lPaUp)|(?<nonce>dWIyNWpaU0k2)|(?<p2c>d01tTWlP)|(?<p2s>d01uTWlPaU)|(?<ppt>d2NIUWlPaU)|(?<sub>emRXSWlPaU)|(?<svt>emRuUWlP)|(?<tag>MFlXY2lPaU)|(?<typ>MGVYQWlPaUp)|(?<url>MWNtd2l)|(?<use>MWMyVWlPaUp)|(?<ver>MlpYSWlPaU)|(?<version>MlpYSnphVzl1SWpv)|(?<x>NElqb2)|(?<x5c>NE5XTWlP)|(?<x5t>NE5YUWlPaU)|(?<x5ts256>NE5YUWpVekkxTmlJNkl)|(?<x5u>NE5YVWlPaU)|(?<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
      "keywords": [
        "zxlk"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "kraken-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[kK][rR][aA][kK][eE][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9\\/=_\\+\\-A-Z]{80,90})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "kraken"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "kucoin-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[kK][uU][cC][oO][iI][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{24})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "kucoin"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "kucoin-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[kK][uU][cC][oO][iI][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "kucoin"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "launchdarkly-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][aA][uU][nN][cC][hH][dD][aA][rR][kK][lL][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "launchdarkly"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "linear-api-key",
      "pattern": "lin_api_[a-z0-9A-Z]{40}",
      "keywords": [
        "lin_api_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "linear-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][iI][nN][eE][aA][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "linear"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "linkedin-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][iI][nN][kK][eE][dD][_\\-]?[iI][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{14})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "linkedin-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][iI][nN][kK][eE][dD][_\\-]?[iI][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{16})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "linkedin",
        "linked_in",
        "linked-in"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "lob-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][oO][bB])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(([lL][iI][vV][eE]|[tT][eE][sS][tT])_[a-f0-9A-F]{35})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "test_",
        "live_"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "lob-pub-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][oO][bB])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(([tT][eE][sS][tT]|[lL][iI][vV][eE])_[pP][uU][bB]_[a-f0-9A-F]{31})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "test_pub",
        "live_pub",
        "_pub"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "looker-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][oO][oO][kK][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{20})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "looker"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "looker-client-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[lL][oO][oO][kK][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{24})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "looker"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mailchimp-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[Mm][aA][iI][lL][cC][hH][iI][mM][pP][Ss][Dd][Kk][^\\n][iI][nN][iI][tT][iI][aA][lL][iI][zZ][eE]|[mM][aA][iI][lL][cC][hH][iI][mM][pP])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{32}-[uU][sS]\\d\\d)(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mailchimp"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mailgun-private-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([kK][eE][yY]-[a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mailgun"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mailgun-pub-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([pP][uU][bB][kK][eE][yY]-[a-f0-9A-F]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mailgun"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mailgun-signing-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][aA][iI][lL][gG][uU][nN])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9A-H]{32}-[a-h0-9A-H]{8}-[a-h0-9A-H]{8})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mailgun"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mapbox-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][aA][pP][bB][oO][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([pP][kK]\\.[a-z0-9A-Z]{60}\\.[a-z0-9A-Z]{22})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mapbox"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "mattermost-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][aA][tT][tT][eE][rR][mM][oO][sS][tT])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{26})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "mattermost"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "maxmind-license-key",
      "pattern": "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "_mmk"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "messagebird-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][eE][sS][sS][aA][gG][eE][_\\-]?[bB][iI][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{25})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "messagebird-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[mM][eE][sS][sS][aA][gG][eE][_\\-]?[bB][iI][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "messagebird",
        "message-bird",
        "message_bird"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "microsoft-teams-webhook",
      "pattern": "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
      "keywords": [
        "webhook.office.com",
        "webhookb2",
        "incomingwebhook"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "netlify-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][eE][tT][lL][iI][fF][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{40,46})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "netlify"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "new-relic-browser-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Jj][Ss]-[a-f0-9A-F]{19})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "nrjs-"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "new-relic-insert-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Ii][Ii]-[a-z0-9\\-A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "nrii-"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "new-relic-user-api-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "new-relic",
        "newrelic",
        "new_relic"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "new-relic-user-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][eE][wW]-[rR][eE][lL][iI][cC]|[nN][eE][wW][rR][eE][lL][iI][cC]|[nN][eE][wW]_[rR][eE][lL][iI][cC])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Nn][Rr][Aa][Kk]-[a-z0-9A-Z]{27})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "nrak"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "notion-api-token",
      "pattern": "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "ntn_"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "npm-access-token",
      "pattern": "\\b([nN][pP][mM]_[a-z0-9A-Z]{36})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "npm_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "nytimes-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[nN][yY][tT][iI][mM][eE][sS]|[nN][eE][wW]-[yY][oO][rR][kK]-[tT][iI][mM][eE][sS],|[nN][eE][wW][yY][oO][rR][kK][tT][iI][mM][eE][sS])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-A-Z]{32})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "nytimes",
        "new-york-times",
        "newyorktimes"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "octopus-deploy-api-key",
      "pattern": "\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "api-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "okta-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[\\w.\\-]{0,50}?(?:(?:[Oo]kta|OKTA))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "okta"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "openai-api-key",
      "pattern": "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_\\-]{74}|[A-Za-z0-9_\\-]{58})T3BlbkFJ(?:[A-Za-z0-9_\\-]{74}|[A-Za-z0-9_\\-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "t3blbkfj"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "openshift-user-token",
      "pattern": "\\b(sha256~[\\w\\-]{43})(?:[^\\w\\-]|$)",
      "keywords": [
        "sha256~"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "perplexity-api-key",
      "pattern": "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)",
      "keywords": [
        "pplx-"
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "plaid-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([aA][cC][cC][eE][sS][sS]-(?:[sS][aA][nN][dD][bB][oO][xX]|[dD][eE][vV][eE][lL][oO][pP][mM][eE][nN][tT]|[pP][rR][oO][dD][uU][cC][tT][iI][oO][nN])-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "plaid"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "plaid-client-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{24})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "plaid"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "plaid-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[pP][lL][aA][iI][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{30})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "plaid"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "planetscale-api-token",
      "pattern": "\\b(pscale_tkn_[\\w=\\.\\-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "pscale_tkn_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "planetscale-oauth-token",
      "pattern": "\\b(pscale_oauth_[\\w=\\.\\-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "pscale_oauth_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "planetscale-password",
      "pattern": "\\b([pP][sS][cC][aA][lL][eE]_[pP][wW]_[\\w=\\.\\-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "pscale_pw_"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "postman-api-token",
      "pattern": "\\b(PMAK-[a-f0-9A-F]{24}\\-[a-f0-9A-F]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "pmak-"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "prefect-api-token",
      "pattern": "\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "pnu_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "private-key",
      "pattern": "-----[Bb][Ee][Gg][Ii][Nn][ A-Z0-9_\\-a-z]{0,100}[Pp][Rr][Ii][Vv][Aa][Tt][Ee] [Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----[\\s\\S\\-]{64,}?[Kk][Ee][Yy](?: [Bb][Ll][Oo][Cc][Kk])?-----",
      "keywords": [
        "-----begin"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "privateai-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[\\w.\\-]{0,50}?(?:[pP][rR][iI][vV][aA][tT][eE][_\\-]?[aA][iI])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "privateai",
        "private_ai",
        "private-ai"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "pulumi-api-token",
      "pattern": "\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "pul-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "pypi-upload-token",
      "pattern": "p\\x79pi-AgEIcHlwaS5vcmc[\\w\\-]{50,1000}",
      "keywords": [
        "pypi-ageichlwas5vcmc"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "rapidapi-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[rR][aA][pP][iI][dD][aA][pP][iI])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_\\-A-Z]{50})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "rapidapi"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "readme-api-token",
      "pattern": "\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "rdme_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "rubygems-api-token",
      "pattern": "\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "rubygems_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "scalingo-api-token",
      "pattern": "\\b(tk-us-[\\w\\-]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "tk-us-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "sendbird-access-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][eE][nN][dD][bB][iI][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sendbird"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "sendbird-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][eE][nN][dD][bB][iI][rR][dD])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sendbird"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "sendgrid-api-token",
      "pattern": "\\b(SG\\.[a-z0-9=_\\-\\.A-Z]{66})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sg."
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "sendinblue-api-token",
      "pattern": "\\b(xkeysib-[a-f0-9]{64}\\-[a-z0-9A-Z]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "xkeysib-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "sentry-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][eE][nN][tT][rR][yY])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sentry"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "sentry-org-token",
      "pattern": "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|$)",
      "keywords": [
        "sntrys_eyjpyxqio"
      ],
      "secretGroup": 0,
      "entropy": 4.5,
      "allowlists": []
    },
    {
      "id": "sentry-user-token",
      "pattern": "\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sntryu_"
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": []
    },
    {
      "id": "settlemint-application-access-token",
      "pattern": "\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sm_aat"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "settlemint-personal-access-token",
      "pattern": "\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sm_pat"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "settlemint-service-access-token",
      "pattern": "\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sm_sat"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "shippo-api-token",
      "pattern": "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "shippo_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "shopify-access-token",
      "pattern": "shpat_[a-fA-F0-9]{32}",
      "keywords": [
        "shpat_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "shopify-custom-access-token",
      "pattern": "shpca_[a-fA-F0-9]{32}",
      "keywords": [
        "shpca_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "shopify-private-app-access-token",
      "pattern": "shppa_[a-fA-F0-9]{32}",
      "keywords": [
        "shppa_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "shopify-shared-secret",
      "pattern": "shpss_[a-fA-F0-9]{32}",
      "keywords": [
        "shpss_"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "sidekiq-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[Bb][Uu][Nn][Dd][Ll][Ee]_[Ee][Nn][Tt][Ee][Rr][Pp][Rr][Ii][Ss][Ee]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm]|[Bb][Uu][Nn][Dd][Ll][Ee]_[Gg][Ee][Mm][Ss]__[Cc][Oo][Nn][Tt][Rr][Ii][Bb][Ss][Yy][Ss]__[Cc][Oo][Mm])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9A-F]{8}:[a-f0-9A-F]{8})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "bundle_enterprise__contribsys__com",
        "bundle_gems__contribsys__com"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "sidekiq-sensitive-url",
      "pattern": "\\b[hH][tT][tT][pP][sS]?://([a-f0-9A-F]{8}:[a-f0-9A-F]{8})@(?:[gG][eE][mM][sS][^\\n][cC][oO][nN][tT][rR][iI][bB][sS][yY][sS][^\\n][cC][oO][mM]|[eE][nN][tT][eE][rR][pP][rR][iI][sS][eE][^\\n][cC][oO][nN][tT][rR][iI][bB][sS][yY][sS][^\\n][cC][oO][mM])(?:[\\/|\\#|\\?|:]|$)",
      "keywords": [
        "gems.contribsys.com",
        "enterprise.contribsys.com"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "slack-app-token",
      "pattern": "[xX][aA][pP][pP]-\\d-[A-Z0-9a-z]+-\\d+-[a-z0-9A-Z]+",
      "keywords": [
        "xapp"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-bot-token",
      "pattern": "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\\-]*",
      "keywords": [
        "xoxb"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "slack-config-access-token",
      "pattern": "[xX][oO][xX][eE][^\\n][xX][oO][xX][bpBP]-\\d-[A-Z0-9a-z]{163,166}",
      "keywords": [
        "xoxe.xoxb-",
        "xoxe.xoxp-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-config-refresh-token",
      "pattern": "[xX][oO][xX][eE]-\\d-[A-Z0-9a-z]{146}",
      "keywords": [
        "xoxe-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-legacy-bot-token",
      "pattern": "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
      "keywords": [
        "xoxb"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-legacy-token",
      "pattern": "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
      "keywords": [
        "xoxo",
        "xoxs"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-legacy-workspace-token",
      "pattern": "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
      "keywords": [
        "xoxa",
        "xoxr"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-user-token",
      "pattern": "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9\\-]{28,34}",
      "keywords": [
        "xoxp-",
        "xoxe-"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "slack-webhook-url",
      "pattern": "(?:https?://)?hooks[^\\n]slack[^\\n]com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
      "keywords": [
        "hooks.slack.com"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "snyk-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][nN][yY][kK][_.\\-]?(?:(?:[aA][pP][iI]|[oO][aA][uU][tT][hH])[_.\\-]?)?(?:[kK][eE][yY]|[tT][oO][kK][eE][nN]))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "snyk"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "sonar-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][oO][nN][aA][rR][_.\\-]?([lL][oO][gG][iI][nN]|[tT][oO][kK][eE][nN]))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:[sS][qQ][uU]_|[sS][qQ][pP]_|[sS][qQ][aA]_)?[a-z0-9=_\\-A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sonar"
      ],
      "secretGroup": 2,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "sourcegraph-access-token",
      "pattern": "\\b(\\b([sS][gG][pP]_(?:[a-fA-F0-9A-Fa-f]{16}|[lL][oO][cC][aA][lL])_[a-fA-F0-9A-Fa-f]{40}|[sS][gG][pP]_[a-fA-F0-9A-Fa-f]{40}|[a-fA-F0-9A-Fa-f]{40})\\b)(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sgp_",
        "sourcegraph"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "square-access-token",
      "pattern": "\\b((?:EAAA|sq0atp-)[\\w\\-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sq0atp-",
        "eaaa"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "squarespace-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[sS][qQ][uU][aA][rR][eE][sS][pP][aA][cC][eE])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "squarespace"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "stripe-access-token",
      "pattern": "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sk_test",
        "sk_live",
        "sk_prod",
        "rk_test",
        "rk_live",
        "rk_prod"
      ],
      "secretGroup": 0,
      "entropy": 2,
      "allowlists": []
    },
    {
      "id": "sumologic-access-id",
      "pattern": "[\\w.\\-]{0,50}?(?:[\\w.\\-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "sumo"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "sumologic-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:(?:[Ss]umo|SUMO))(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{64})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "sumo"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "telegram-bot-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][eE][lL][eE][gG][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?:A)[a-z0-9_\\-A-Z]{34})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "telegr"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "travisci-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][rR][aA][vV][iI][sS])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{22})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "travis"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twilio-api-key",
      "pattern": "SK[0-9a-fA-F]{32}",
      "keywords": [
        "sk"
      ],
      "secretGroup": 0,
      "entropy": 3,
      "allowlists": []
    },
    {
      "id": "twitch-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][cC][hH])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{30})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitch"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twitter-access-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{45})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twitter-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9A-Za-z]{20,40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twitter-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{25})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twitter-api-secret",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{50})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "twitter-bearer-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][wW][iI][tT][tT][eE][rR])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Aa]{22}[a-zA-Z0-9%A-Za-z]{80,100})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "twitter"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "typeform-api-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[tT][yY][pP][eE][fF][oO][rR][mM])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([tT][fF][pP]_[a-z0-9\\-_\\.=A-Z]{59})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "tfp_"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "vault-batch-token",
      "pattern": "\\b(hvb\\.[\\w\\-]{138,300})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "hvb."
      ],
      "secretGroup": 0,
      "entropy": 4,
      "allowlists": []
    },
    {
      "id": "vault-service-token",
      "pattern": "\\b((?:hvs\\.[\\w\\-]{90,120}|s\\.(?:[a-z0-9A-Z]{24})))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
      "keywords": [
        "hvs.",
        "s."
      ],
      "secretGroup": 0,
      "entropy": 3.5,
      "allowlists": [
        {
          "patterns": [
            "s\\.[A-Za-z]{24}"
          ],
          "stopwords": [],
          "target": "secret"
        }
      ]
    },
    {
      "id": "yandex-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([tT]1\\.[A-Z0-9a-z_\\-a-zA-Z]+[=]{0,2}\\.[A-Z0-9a-z_\\-a-zA-Z]{86}[=]{0,2})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "yandex"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "yandex-api-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Aa][Qq][Vv][Nn][A-Za-z0-9_\\-a-zA-Z]{35,38})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "yandex"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "yandex-aws-access-token",
      "pattern": "[\\w.\\-]{0,50}?(?:[yY][aA][nN][dD][eE][xX])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([Yy][Cc][a-zA-Z0-9_\\-A-Za-z]{38})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "yandex"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    },
    {
      "id": "zendesk-secret-key",
      "pattern": "[\\w.\\-]{0,50}?(?:[zZ][eE][nN][dD][eE][sS][kK])(?:[ \\t\\w.\\-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9A-Z]{40})(?:[\\x60'\"\\s;]|\\\\[nrNR]|$)",
      "keywords": [
        "zendesk"
      ],
      "secretGroup": 0,
      "entropy": 0,
      "allowlists": []
    }
  ],
  "allowlists": [
    {
      "patterns": [
        "^(?:[tT][rR][uU][eE]|[fF][aA][lL][sS][eE]|[nN][uU][lL][lL])$",
        "^(?:[aA]+|[bB]+|[cC]+|[dD]+|[eE]+|[fF]+|[gG]+|[hH]+|[iI]+|[jJ]+|[kK]+|[lL]+|[mM]+|[nN]+|[oO]+|[pP]+|[qQ]+|[rR]+|[sS]+|[tT]+|[uU]+|[vV]+|[wW]+|[xX]+|[yY]+|[zZ]+|\\*+|\\.+)$",
        "^\\$(?:\\d+|{\\d+})$",
        "^\\$(?:[A-Z_]+|[a-z_]+)$",
        "^\\${(?:[A-Z_]+|[a-z_]+)}$",
        "^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$",
        "^\\$\\{\\{[ \\t]*(?:(?:env|github|secrets|vars)(?:\\.[A-Za-z]\\w+)+[\\w \"'&./=|]*)[ \\t]*}}$",
        "^%(?:[A-Z_]+|[a-z_]+)%$",
        "^%[+\\-# 0]?[b\\x63deEfFgGoOpqstTUvxX]$",
        "^\\{\\d{0,2}}$",
        "^@(?:[A-Z_]+|[a-z_]+)@$",
        "^/Users/[a-z0-9A-Z]+/[\\w .-/]+$",
        "^/(?:bin|etc|home|opt|tmp|usr|var)/[\\w ./\\-]+$"
      ],
      "stopwords": [
        "014df517-39d1-4453-b7b3-9930c563627c",
        "abcdefghijklmnopqrstuvwxyz"
      ],
      "target": "secret"
    }
  ]
}
