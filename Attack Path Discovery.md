# Joinable Exchange Distribution Lists: An Overlooked Assumed-Breach Attack Path

## Introduction

As part of my typical internal pentest methodology, I like to include a two-pronged approach consisting of both unauthenticated and authenticated vulnerability discovery. This helps uncover vulnerabilities across the network, as well as within Active Directory, Microsoft, and other internally provisioned software and services.

This is usually a very fruitful combination, and while many vulnerabilities initially discovered without authentication can demonstrate an increased level of impact, they often fall short without the discovery of a valid set of domain credentials. That said, credentials can often be obtained through common techniques such as file share enumeration, Kerberoasting, password spraying, and similar attacks. While I always check for these common culprits, having a set of valid credentials ready to go gives me a leg up in discovery, enumeration, and exploitation.

Taking an "assumed breach" approach, where a baseline standard user account is provisioned for testing, provides an immediate advantage when it comes to identifying impactful and exploitable vulnerabilities. After all, humans are the weakest link in any organization, and it is not a matter of if a compromise will happen, but when.

## Enumerating Microsoft Portals

On a recent pentest, I've taken a liking to <https://msportals.io/?search=>, a comprehensive directory of Microsoft portals created and maintained by Adam Fowler.

With it, I've taken a manual approach of clicking through each portal to quickly learn about a company's Microsoft security posture by seeing what a standard user can access, click through, and even modify.

I'd definitely recommend checking this list out to see whether your organization restricts potentially sensitive admin portals, Microsoft APIs, and other functionality. The more restrictive your organization can be, the better, because many organizations are unknowingly configured to allow access to a surprising number of these locations by default.

## Exchange Admin Center

The portal I want to discuss today is the Exchange Admin Center (EAC):

<https://admin.cloud.microsoft/exchange#/homepage>

While navigating to this URL in a client's environment, I found the `/groups` URI through the GUI, and to my surprise, the **+ Join** option opened an **All Groups** blade that listed an expanding collection of Exchange groups and their associated distribution lists.

I could continue scrolling through the list, loading 120 at a time, and when clicking into individual group names, I could view:

- Membership information
- Owners
- Members
- A **+ Join Group** option

Surely I wouldn't be able to add myself to additional groups as a base-level user, right?

That's when I discovered that under the **Members** tab, there was a **Membership Requests** header with a single line stating:

> Requests to Join are Automatically Approved.

Don't mind if I do.

## Self-Adding to Distribution Lists

Moments later, I was selecting multiple groups, checking their request-to-join status, and adding myself to them with seemingly no issue.

To my surprise, the groups I could see were becoming more and more interesting:

- Admin distribution lists
- IT support distribution lists
- Private groups
- Service email distribution lists

Finding an obscure test group with no other associated members, I added myself to the distribution list and attempted to send a test email to the associated address.

A moment later, Outlook was dinging with a new alert.

Finding a few more interesting targets, I added myself and sat back to wait.

To my surprise, IT support-related tickets started flooding my inbox.

A treasure trove of environmental information and potential details that could be leveraged in a social engineering campaign.

## Taking It Further

And that's when my adversarial mindset kicked it up a gear.

Knowing that poor security practices often plague enterprises, my next thought was:

> What email groups could I add myself to, and how can I leverage them for more access?

Three lines of PowerShell later, I had a simple way to identify every email address with an open member join restriction.

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
Import-Module -Name ExchangeOnlineManagement

Get-DistributionGroup -Filter "MemberJoinRestriction -eq 'Open'" |
    Select DisplayName, PrimarySmtpAddress, MemberJoinRestriction, ManagedBy
```

Filtering through the list, I found several contenders that included "admin" and the names of critical SaaS platforms.

Distribution lists that appeared to be shared login accounts for financial management systems.

Adding myself to one of the groups with a single click, I navigated to the software provider's login page, clicked the **Forgot Password** option, entered the shared login account, and hit send.

The familiar ding only moments later was all I needed to know that this was a viable attack vector.

## Research and Tooling

Digging around online, I didn't find much documentation on this attack path.

That's when I reached out to ThoughtContagion, the foremost Microsoft security expert I know, who has published more than 350 security checks across Microsoft, Microsoft 365, Entra ID, and related technologies.

I figured he'd tell me he already had a script in place.

When that wasn't the case, he was more than willing to put together a proof of concept before I could blink.

And there we had it:

- A fully functional PowerShell script to enumerate joinable distribution lists
- A new attack vector that I'll be incorporating into future assumed-breach assessments

Not to mention the additional enumeration that ThoughtContagion incorporated to take the script to the next level.

Check out the README for its checks covering:

- Public Microsoft 365 groups
- Distribution lists and mail-enabled security groups
- Dynamic membership groups
- Privilege correlation
- Policy correlation

## Final Thoughts

This attack path stood out because it combined several things that are often overlooked:

1. Excessive visibility into Exchange groups
2. Automatically approved group membership requests
3. Shared or privileged email distribution lists
4. Password reset workflows tied to group-managed mailboxes

Individually, these issues may seem low risk. Combined, they can provide meaningful opportunities for lateral movement, information gathering, account compromise, and social engineering.

Why is "Open - Anyone can join this group without owner approval" the default selected configuration when creating new Exchange groups?
Just another reason to be MAAD AT Microsoft

Huge thanks to @ThoughtContagion
He is a master of his craft, and I'm psyched that he was able to take this initial discovery to the next level.
