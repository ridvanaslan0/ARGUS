#include "ck/tool.h"
#include "ck/kit.h"

#include <algorithm>

namespace ck {

Registry& Registry::instance() {
    static Registry r;
    return r;
}

void Registry::add(Tool t) { tools_.push_back(std::move(t)); }

const Tool* Registry::find(const std::string& name) const {
    for (auto& t : tools_)
        if (t.name == name) return &t;
    return nullptr;
}

std::vector<std::string> Registry::categories() const {
    std::vector<std::string> out;
    for (auto& t : tools_)
        if (std::find(out.begin(), out.end(), t.category) == out.end())
            out.push_back(t.category);
    return out;
}

ToolRegistrar::ToolRegistrar(const char* name, const char* category, const char* brief,
                             const char* usage, ToolFn fn) {
    Registry::instance().add(Tool{name, category, brief, usage, fn});
}

}  // namespace ck