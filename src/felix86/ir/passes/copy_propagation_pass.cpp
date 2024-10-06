#include "felix86/ir/passes/passes.hpp"

void ir_copy_propagate_node(const IRDominatorTreeNode* node, std::unordered_map<IRInstruction*, IRInstruction*> map) {
    std::list<IRInstruction>& insts = node->block->GetInstructions();
    auto it = insts.begin();
    auto end = insts.end();
    while (it != end) {
        if (it->GetOpcode() == IROpcode::Mov) {
            IRInstruction* value_final = it->GetOperand(0);
            bool found_once = false;
            while (map.find(value_final) != map.end()) {
                found_once = true;
                value_final = map[value_final];
            }
            map[&*it] = value_final;
            // If it's the mov operand was already in the map, that means it was also removed
            // This can happen if you have sequential movs like so:
            // mov a, b
            // mov c, a
            // When the pass go through, it will remove `a`. So we don't need to remove a use
            // from a as it's removed from the list and it would be invalid to do so anyway.
            // We still need to keep it in the map though for instructions that could be using
            // it further down the line.
            if (!found_once) {
                it->Invalidate();
            }
            it = insts.erase(it);
        } else {
            switch (it->GetExpressionType()) {
            case ExpressionType::Operands: {
                Operands& operands = it->AsOperands();
                for (IRInstruction*& operand : operands.operands) {
                    auto found = map.find(operand);
                    if (found != map.end()) {
                        operand = found->second;
                        operand->AddUse();
                    }
                }
                break;
            }
            case ExpressionType::Immediate:
            case ExpressionType::GetGuest:
            case ExpressionType::Comment: {
                break;
            }
            case ExpressionType::SetGuest: {
                SetGuest& set_guest = it->AsSetGuest();
                auto found = map.find(set_guest.source);
                if (found != map.end()) {
                    set_guest.source = found->second;
                    set_guest.source->AddUse();
                }
                break;
            }
            case ExpressionType::Phi: {
                Phi& phi = it->AsPhi();
                for (size_t i = 0; i < phi.blocks.size(); i++) {
                    auto found = map.find(phi.values[i]);
                    if (found != map.end()) {
                        phi.values[i] = found->second;
                        phi.values[i]->AddUse();
                    }
                }
                break;
            }
            default: {
                UNREACHABLE();
            }
            }
            ++it;
        }
    }

    for (const auto& child : node->children) {
        ir_copy_propagate_node(child, map);
    }
}

void ir_replace_operand(IRInstruction*& operand) {
    if (operand->GetOpcode() != IROpcode::Mov) {
        return;
    }

    bool is_mov = true;
    IRInstruction* value_final = operand->GetOperand(0);
    do {
        is_mov = false;
        if (value_final->GetOpcode() == IROpcode::Mov) {
            value_final = value_final->GetOperand(0);
            is_mov = true;
        }
    } while (is_mov);
    operand->RemoveUse();
    operand = value_final;
    operand->AddUse();
}

void ir_copy_propagate_node_v2(const IRDominatorTreeNode* node) {
    IRBlock* block = node->block;

    for (IRInstruction& inst : block->GetInstructions()) {
        if (inst.GetOpcode() != IROpcode::Mov) {
            switch (inst.GetExpressionType()) {
            case ExpressionType::Operands: {
                Operands& operands = inst.AsOperands();
                for (IRInstruction*& operand : operands.operands) {
                    ir_replace_operand(operand);
                }
                break;
            }
            case ExpressionType::Immediate:
            case ExpressionType::GetGuest:
            case ExpressionType::Comment: {
                break;
            }
            case ExpressionType::SetGuest: {
                SetGuest& set_guest = inst.AsSetGuest();
                ir_replace_operand(set_guest.source);
                break;
            }
            case ExpressionType::Phi: {
                Phi& phi = inst.AsPhi();
                for (size_t i = 0; i < phi.blocks.size(); i++) {
                    ir_replace_operand(phi.values[i]);
                }
                break;
            }
            default: {
                UNREACHABLE();
            }
            }
        }
    }

    for (const auto& child : node->children) {
        ir_copy_propagate_node_v2(child);
    }
}

void ir_copy_propagation_pass(IRFunction* function) {
    const IRDominatorTree& dominator_tree = function->GetDominatorTree();

    const IRDominatorTreeNode& node = dominator_tree.nodes[0];
    std::unordered_map<IRInstruction*, IRInstruction*> copy_map;
    ir_copy_propagate_node_v2(&node);
}
