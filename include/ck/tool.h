#pragma once

#include <string>
#include <vector>
#include <functional>

namespace ck {

class Args {
public:
    Args(std::vector<std::string> argv) : v_(std::move(argv)) {}

    const std::vector<std::string>& all() const { return v_; }
    size_t size() const { return v_.size(); }
    bool empty() const { return v_.empty(); }

    std::string at(size_t i, const std::string& def = "") const {
        return i < v_.size() ? v_[i] : def;
    }

    bool has(const std::string& flag) const {
        for (auto& s : v_)
            if (s == flag || s == "--" + flag) return true;
        return false;
    }

    bool flag(const std::string& name) const {
        for (auto& s : v_)
            if (s == "--" + name || s == "-" + name) return true;
        return false;
    }

    std::string opt(const std::string& name, const std::string& def = "") const {
        std::string want = "--" + name;
        for (size_t i = 0; i < v_.size(); ++i) {
            const std::string& s = v_[i];
            if (s == want) return i + 1 < v_.size() ? v_[i + 1] : def;
            if (s.rfind(want + "=", 0) == 0) return s.substr(want.size() + 1);
        }
        return def;
    }

    bool hasOpt(const std::string& name) const {
        std::string want = "--" + name;
        for (auto& s : v_)
            if (s == want || s.rfind(want + "=", 0) == 0) return true;
        return false;
    }

    bool optInt(const std::string& name, int def, int& out) const {
        if (!hasOpt(name)) return false;
        out = std::stoi(opt(name, std::to_string(def)));
        return true;
    }

    double optDouble(const std::string& name, double def, double& out) const {
        if (!hasOpt(name)) return false;
        out = std::stod(opt(name, std::to_string(def)));
        return true;
    }

    bool isBooleanFlag(const std::string& bare) const {
        static const char* const kBoolFlags[] = {
            "all-files", "b64", "banner", "crack", "detail", "enum", "no-ambiguous",
            "no-caps", "no-digits", "no-follow", "no-lower", "no-recursive", "no-repeat",
            "no-upper", "passphrase", "selftest", "show-clean", "show-closed", "stdin",
            "symbols", "i-own-this", "help", "version", "quiet", "json"};
        for (const char* f : kBoolFlags)
            if (bare == f) return true;
        return false;
    }

    std::vector<std::string> positionals() const {
        std::vector<std::string> out;
        for (size_t i = 0; i < v_.size(); ++i) {
            const std::string& s = v_[i];
            if (s.rfind("--", 0) == 0) {
                if (s.find('=') == std::string::npos && !isBooleanFlag(s.substr(2)) &&
                    i + 1 < v_.size() && v_[i + 1].rfind("-", 0) != 0)
                    ++i;
                continue;
            }
            out.push_back(s);
        }
        return out;
    }

    std::string first() const {
        auto p = positionals();
        return p.empty() ? "" : p[0];
    }

private:
    std::vector<std::string> v_;
};

using ToolFn = std::function<int(const Args&)>;

struct Tool {
    std::string name;
    std::string category;
    std::string brief;
    std::string usage;
    ToolFn run;
};

class Registry {
public:
    static Registry& instance();
    void add(Tool t);
    const std::vector<Tool>& all() const { return tools_; }
    const Tool* find(const std::string& name) const;
    std::vector<std::string> categories() const;

private:
    std::vector<Tool> tools_;
};

struct ToolRegistrar {
    ToolRegistrar(const char* name, const char* category, const char* brief,
                  const char* usage, ToolFn fn);
};

#define CK_TOOL(name, category, brief, usage, fn)                              \
    static ::ck::ToolRegistrar ck_reg_##fn(name, category, brief, usage, fn)

}  // namespace ck