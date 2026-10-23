// Families that are defined by what is found together rather than by one sign:
// a trojan is a disguise plus harm, a RAT is a remote shell plus the tools of
// spying, a backdoor is a shell that comes back, a botnet is a controller channel
// plus spreading. The engines report the single signs; this pass reads them per
// process (dynamic) or per file (scan, static) and adds the family.
#include "malware.h"
#include "protocol.h"
#include "report.h"

#include <functional>
#include <map>
#include <set>
#include <string>

namespace lcreport {
namespace {

using Types = std::set<std::string>;

bool has_any(const Types &t, std::initializer_list<const char *> of) {
    for (const char *x : of)
        if (t.count(x))
            return true;
    return false;
}

std::string listed(const Types &t, std::initializer_list<const char *> of) {
    std::string out;
    for (const char *x : of)
        if (t.count(x))
            out += (out.empty() ? "" : ", ") + std::string(x);
    return out;
}

std::string group_of(const Report &r, const Finding &f) {
    if (r.mode == "dynamic")
        return "pid " + std::to_string(f.pid);
    return f.access.empty() ? std::string() : f.access.front().file;
}

} // namespace

void add_composite_findings(Report &r) {
    std::map<std::string, Types> seen;
    std::map<std::string, const Finding *> first; // where a group's first finding is
    for (const Finding &f : r.findings) {
        if (f.category != lcproto::kCatSecurity && f.category != lcproto::kCatScan)
            continue;
        const std::string g = group_of(r, f);
        seen[g].insert(f.type);
        first.emplace(g, &f);
    }
    std::vector<Finding> added;
    for (auto &[group, t] : seen) {
        const Finding &base = *first[group];
        auto add = [&](const char *type, const std::string &why) {
            if (t.count(type))
                return;
            Finding f;
            f.type = type;
            f.category = base.category;
            f.message = why;
            f.pid = base.pid;
            f.tid = base.tid;
            f.access = base.access;
            f.key = std::to_string(std::hash<std::string>{}(std::string(type) + "|" + group + "|" + why));
            added.push_back(std::move(f));
            t.insert(type);
        };
        const std::string where = r.mode == "dynamic" ? "the program" : "this file";

        // implications: one sign that is two families' names
        if (t.count(lcproto::kFileInfector))
            add(lcproto::kVirus, where + " puts its code into other executables: a virus spreads that way");
        if (t.count(lcproto::kPropagation))
            add(lcproto::kWorm, where + " spreads over the network by itself: that is a worm");
        if (t.count(lcproto::kWorm))
            add(lcproto::kPropagation, where + " is a worm, which propagates over the network");
        if (t.count(lcproto::kNetScan) && r.mode == "dynamic") {
            add(lcproto::kPropagation, "the program tried a hundred addresses and ports in ten seconds: "
                                       "network-propagating malware looks for its next victim this way");
            add(lcproto::kWorm, where + " tried a hundred addresses and ports in ten seconds, as a worm does");
        }

        // a disguise together with anything harmful
        const bool disguised = has_any(t, {lcproto::kMasquerade, lcproto::kDisguised});
        const bool harmful =
            has_any(t, {lcproto::kReverseShell, lcproto::kDropper, lcproto::kFileless, lcproto::kCredAccess,
                        lcproto::kInjection, lcproto::kDestructive, lcproto::kMiner, lcproto::kKeylogger,
                        lcproto::kSpyware, lcproto::kRansom, lcproto::kBackdoor, lcproto::kInfostealer,
                        lcproto::kRootkit, lcproto::kWiper, lcproto::kFileWiper, lcproto::kBotnet,
                        lcproto::kRat, lcproto::kMalware, lcproto::kPersistence, lcproto::kLogTamper,
                        lcproto::kObfuscated, lcproto::kSuspiciousBin, lcproto::kVirus, lcproto::kWorm,
                        lcproto::kFakeAv, lcproto::kExtortion, lcproto::kScreenLocker, lcproto::kMicEavesdrop,
                        lcproto::kCamHijack, lcproto::kScreenGrabber, lcproto::kMalExtension, lcproto::kClickFraud,
                        lcproto::kDialer, lcproto::kRecoveryBlock, lcproto::kIcsMalware, lcproto::kCloudMalware,
                        lcproto::kContainerEscape, lcproto::kHypervisorEscape, lcproto::kC2Beacon, lcproto::kStager,
                        lcproto::kProcessHollowing, lcproto::kProcessDoppel, lcproto::kDllHijack, lcproto::kComHijack,
                        lcproto::kBackupWiper, lcproto::kSeedStealer, lcproto::kTokenStealer, lcproto::kGameStealer,
                        lcproto::kEmailStealer, lcproto::kVpnStealer, lcproto::kKerberosAttack, lcproto::kCookieHijack,
                        lcproto::kMfaBypass, lcproto::kWebShell, lcproto::kWebMiner, lcproto::kDigitalSkimmer,
                        lcproto::kByovd, lcproto::kSecurityDisabler, lcproto::kLogWiper, lcproto::kMbrLocker,
                        lcproto::kVbrDestroyer, lcproto::kNetSniffer, lcproto::kArpSpoofer, lcproto::kReconTool,
                        lcproto::kBruteForcer, lcproto::kDepConfusion, lcproto::kBuildTrojan, lcproto::kKernelExploit,
                        lcproto::kHardwareImplant, lcproto::kAiMalware});
        if (disguised && harmful)
            add(lcproto::kTrojan,
                where + " pretends to be something it is not (" +
                    listed(t, {lcproto::kMasquerade, lcproto::kDisguised}) + ") and also does or carries harm (" +
                    listed(t, {lcproto::kReverseShell, lcproto::kDropper, lcproto::kFileless,
                               lcproto::kCredAccess, lcproto::kInjection, lcproto::kDestructive,
                               lcproto::kMiner, lcproto::kKeylogger, lcproto::kSpyware, lcproto::kRansom,
                               lcproto::kBackdoor, lcproto::kInfostealer, lcproto::kRootkit,
                               lcproto::kMalware, lcproto::kPersistence, lcproto::kObfuscated,
                               lcproto::kSuspiciousBin}) +
                    "): a program that looks like one thing and is another is a trojan horse");

        // a shell for the network that comes back after a restart
        if (t.count(lcproto::kReverseShell) && t.count(lcproto::kPersistence))
            add(lcproto::kBackdoor, where + " gives a shell to the network and arranges to run again at "
                                            "login or boot: a way back in that survives a restart");
        // a remote shell plus the tools of spying
        if (t.count(lcproto::kReverseShell) &&
            has_any(t, {lcproto::kKeylogger, lcproto::kSpyware, lcproto::kCredAccess, lcproto::kInfostealer,
                        lcproto::kInjection, lcproto::kPersistence}))
            add(lcproto::kRat,
                where + " gives a remote command line (reverse-shell) and also " +
                    listed(t, {lcproto::kKeylogger, lcproto::kSpyware, lcproto::kCredAccess,
                               lcproto::kInfostealer, lcproto::kInjection, lcproto::kPersistence}) +
                    ": the abilities of a remote access trojan");
        // a controller channel together with spreading or a way to run commands
        if (has_any(t, {lcproto::kIrcBot, lcproto::kDdos}) &&
            has_any(t, {lcproto::kReverseShell, lcproto::kDropper, lcproto::kPersistence, lcproto::kNetScan,
                        lcproto::kPropagation, lcproto::kWorm}))
            add(lcproto::kBotnet,
                where + " has a bot's controller channel or attack (" +
                    listed(t, {lcproto::kIrcBot, lcproto::kDdos}) + ") together with " +
                    listed(t, {lcproto::kReverseShell, lcproto::kDropper, lcproto::kPersistence,
                               lcproto::kNetScan, lcproto::kPropagation, lcproto::kWorm}) +
                    ": it takes orders and carries them out");
    }
    for (Finding &f : added)
        r.findings.push_back(std::move(f));
}

} // namespace lcreport
