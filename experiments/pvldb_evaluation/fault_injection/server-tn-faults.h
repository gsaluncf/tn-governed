// Fault hooks compiled only into the evaluation server. The packaged TN server
// contains none of this code. TN_FAULT selects one mutation at each boundary:
// task_* changes a prepared task before the slot gate, decrypt_* changes the
// model's decrypt call before Rust validates it, and result_* changes the report
// turn's result before Rust validates it.
#pragma once

#include <cstdlib>
#include <functional>
#include <string>

#include "server-common.h"
#include "server-task.h"

inline std::string tn_fault_setting(const char * name) {
    const char * value = std::getenv(name);
    return value == nullptr ? std::string() : std::string(value);
}

inline std::string tn_fault_replace(std::string text, const std::string & from, const std::string & to) {
    const size_t position = text.find(from);
    if (from.empty() || position == std::string::npos) {
        throw std::runtime_error("fault target is absent from the model output");
    }
    return text.replace(position, from.size(), to);
}

inline void tn_fault_mutate_task(server_task & task) {
    const std::string fault = tn_fault_setting("TN_FAULT");
    if (fault == "task_prompt_token_replaced") {
        const llama_tokens & tokens = task.tokens.get_tokens();
        const llama_pos position = static_cast<llama_pos>(tokens.size() / 2);
        task.tokens.set_token(position, tokens[position] == tokens[0] ? tokens[1] : tokens[0]);
    } else if (fault == "task_governance_tokens_removed") {
        llama_tokens tokens = task.tokens.get_tokens();
        const size_t quarter = tokens.size() / 4;
        tokens.erase(tokens.begin() + quarter, tokens.begin() + 2 * quarter);
        task.tokens = server_tokens(tokens, false);
    } else if (fault == "task_predict_limit_raised") {
        task.params.n_predict += 1;
    } else if (fault == "task_temperature_changed") {
        task.params.sampling.temp += 0.5f;
    } else if (fault == "task_stop_string_added") {
        task.params.antiprompt.push_back("TN_FAULT_STOP");
    } else if (fault == "task_prompt_cache_enabled") {
        task.params.cache_prompt = !task.params.cache_prompt;
    } else if (fault == "task_tool_grammar_removed") {
        task.params.sampling.grammar = common_grammar();
        task.params.sampling.grammar_triggers.clear();
    } else if (fault == "task_rendered_prompt_changed") {
        task.tn_rendered_prompt += " ";
    } else if (fault == "task_request_body_changed") {
        task.tn_request_json += " ";
    } else if (fault == "task_manifest_cleared") {
        task.tn_runnable_manifest.clear();
    } else if (fault == "task_type_changed") {
        task.type = SERVER_TASK_TYPE_INFILL;
    } else if (fault == "task_turn_detached") {
        task.tn_turn = nullptr;
    }
}

inline void tn_fault_rewrite_html(
        common_chat_msg & message,
        const std::function<std::string(const std::string &)> & rewrite) {
    json arguments = json::parse(message.tool_calls.at(0).arguments);
    arguments["report_html"] = rewrite(arguments.at("report_html").get<std::string>());
    message.tool_calls.at(0).arguments = arguments.dump();
}

inline std::string tn_fault_flip(std::string hash) {
    char & last = hash.back();
    last = last == '0' ? '1' : '0';
    return hash;
}

inline void tn_fault_mutate_decrypt(common_chat_msg & message, const std::string & fault) {
    json arguments = json::parse(message.tool_calls.at(0).arguments);
    if (fault == "decrypt_governance_hash_changed") {
        arguments["governance_hash"] = tn_fault_flip(arguments.at("governance_hash").get<std::string>());
    } else if (fault == "decrypt_data_hash_changed") {
        arguments["data_hashes"][0] = tn_fault_flip(arguments.at("data_hashes").at(0).get<std::string>());
    } else if (fault == "decrypt_hashes_swapped") {
        const json governance = arguments.at("governance_hash");
        arguments["governance_hash"] = arguments.at("data_hashes").at(0);
        arguments["data_hashes"][0] = governance;
    } else if (fault == "decrypt_governance_hash_removed") {
        arguments.erase("governance_hash");
    } else if (fault == "decrypt_data_hashes_empty") {
        arguments["data_hashes"] = json::array();
    } else if (fault == "decrypt_extra_argument") {
        arguments["group"] = "tn.agents";
    } else if (fault == "decrypt_tool_renamed") {
        message.tool_calls.at(0).name = "decrypt_all";
    }
    message.tool_calls.at(0).arguments = arguments.dump();
}

inline void tn_fault_mutate_result(server_task_result_cmpl_final & result) {
    const std::string fault = tn_fault_setting("TN_FAULT");
    common_chat_msg & message = result.oaicompat_msg;
    const bool decrypt_turn = !message.tool_calls.empty() && message.tool_calls.at(0).name == "decrypt_value";
    if (decrypt_turn && fault.rfind("decrypt_", 0) == 0) {
        tn_fault_mutate_decrypt(message, fault);
    }
    if (decrypt_turn || fault.rfind("result_", 0) != 0) {
        return;
    }
    const std::string notice = tn_fault_setting("TN_FAULT_NOTICE");
    if (fault == "result_truncated") {
        result.truncated = true;
    } else if (fault == "result_stopped_at_limit") {
        result.stop = STOP_TYPE_LIMIT;
    } else if (fault == "result_no_tool_call") {
        message.tool_calls.clear();
    } else if (fault == "result_two_tool_calls") {
        message.tool_calls.push_back(message.tool_calls.at(0));
    } else if (fault == "result_prose_with_call") {
        result.content = "The report is complete.";
        message.content = result.content;
    } else if (fault == "result_unknown_tool") {
        message.tool_calls.at(0).name = "send_external_email";
    } else if (fault == "result_malformed_arguments") {
        message.tool_calls.at(0).arguments = "{";
    } else if (fault == "result_extra_argument") {
        json arguments = json::parse(message.tool_calls.at(0).arguments);
        arguments["source_object_id"] = "sha256:" + std::string(64, '0');
        message.tool_calls.at(0).arguments = arguments.dump();
    } else if (fault == "result_notice_removed") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, notice, "");
        });
    } else if (fault == "result_notice_changed") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, "Human review is pending", "Human review is complete");
        });
    } else if (fault == "result_notice_in_comment") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, notice, "<!-- " + notice + " -->");
        });
    } else if (fault == "result_notice_in_script") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, notice, "<script>" + notice + "</script>");
        });
    } else if (fault == "result_notice_in_style") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, notice, "<style>" + notice + "</style>");
        });
    } else if (fault == "result_amount_changed") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, "ACME: ", "ACME: 9");
        });
    } else if (fault == "result_external_image") {
        tn_fault_rewrite_html(message, [&](const std::string & html) {
            return tn_fault_replace(html, "</body>", "<img src=\"http://collector.invalid/x\"></body>");
        });
    }
}
