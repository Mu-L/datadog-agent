// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:generate operators -output eval_operators.go

// Package eval holds eval related files
package eval

import (
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/alecthomas/participle/lexer"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/ast"
)

// defines factor applied by specific operator
const (
	FunctionWeight       = 5
	InArrayWeight        = 10
	HandlerWeight        = 50
	PatternWeight        = 80
	RegexpWeight         = 100
	InPatternArrayWeight = 1000
	IteratorWeight       = 2000
)

// BoolEvalFnc describe a eval function return a boolean
type BoolEvalFnc = func(ctx *Context) bool

func extractField(field string, state *State) (Field, Field, RegisterID, error) {
	if state.regexpCache.arraySubscriptFindRE == nil {
		state.regexpCache.arraySubscriptFindRE = regexp.MustCompile(`\[([^\]]*)\]`)
	}
	if state.regexpCache.arraySubscriptReplaceRE == nil {
		state.regexpCache.arraySubscriptReplaceRE = regexp.MustCompile(`(.+)\[[^\]]+\](.*)`)
	}

	var regID RegisterID
	ids := state.regexpCache.arraySubscriptFindRE.FindStringSubmatch(field)

	switch len(ids) {
	case 0:
		return field, "", "", nil
	case 2:
		regID = ids[1]
	default:
		return "", "", "", fmt.Errorf("wrong register format for fields: %s", field)
	}

	resField := state.regexpCache.arraySubscriptReplaceRE.ReplaceAllString(field, `$1$2`)
	itField := state.regexpCache.arraySubscriptReplaceRE.ReplaceAllString(field, `$1`)

	return resField, itField, regID, nil
}

type ident struct {
	Pos   lexer.Position
	Ident *string
}

func identToEvaluator(obj *ident, opts *Opts, state *State) (interface{}, lexer.Position, error) {
	if accessor, ok := opts.Constants[*obj.Ident]; ok {
		return accessor, obj.Pos, nil
	}

	if state.macros != nil {
		if macro, ok := state.macros.GetMacroEvaluator(*obj.Ident); ok {
			return macro.Value, obj.Pos, nil
		}
	}

	field, itField, regID, err := extractField(*obj.Ident, state)
	if err != nil {
		return nil, obj.Pos, err
	}

	// transform extracted field to support legacy SECL fields
	if opts.LegacyFields != nil {
		if newField, ok := opts.LegacyFields[field]; ok {
			field = newField
		}
	}

	evaluator, err := state.model.GetEvaluator(field, regID, obj.Pos.Offset)
	if err != nil {
		return nil, obj.Pos, err
	}

	state.UpdateFields(field)

	if regID != "" {
		// avoid wildcard register for the moment
		if regID == "_" {
			return nil, obj.Pos, NewError(obj.Pos, "`_` can't be used as a iterator variable name")
		}

		// avoid using the same register on two different fields
		if slices.ContainsFunc(state.registers, func(r Register) bool {
			return r.ID == regID && r.Field != itField
		}) {
			return nil, obj.Pos, NewError(obj.Pos, "iterator variable used by different fields '%s'", regID)
		}

		if !slices.ContainsFunc(state.registers, func(r Register) bool {
			return r.ID == regID
		}) {
			state.registers = append(state.registers, Register{ID: regID, Field: itField})
		}
	}

	return evaluator, obj.Pos, nil
}

func arrayToEvaluator(array *ast.Array, opts *Opts, state *State) (interface{}, lexer.Position, error) {
	if len(array.Numbers) != 0 {
		var evaluator IntArrayEvaluator
		evaluator.AppendValues(array.Numbers...)
		return &evaluator, array.Pos, nil
	} else if len(array.StringMembers) != 0 {
		var evaluator StringValuesEvaluator
		evaluator.AppendMembers(array.StringMembers...)
		return &evaluator, array.Pos, nil
	} else if array.Ident != nil {
		if state.macros != nil {
			if macro, ok := state.macros.GetMacroEvaluator(*array.Ident); ok {
				return macro.Value, array.Pos, nil
			}
		}

		// could be an iterator
		return identToEvaluator(&ident{Pos: array.Pos, Ident: array.Ident}, opts, state)
	} else if len(array.Idents) != 0 {
		// Only "Constants" idents are supported, and only string, int and boolean constants are expected.
		// Determine the type with the first ident
		switch reflect.TypeOf(opts.Constants[array.Idents[0]]) {
		case reflect.TypeOf(&IntEvaluator{}):
			var evaluator IntArrayEvaluator
			for _, item := range array.Idents {
				itemEval, ok := opts.Constants[item].(*IntEvaluator)
				if !ok {
					return nil, array.Pos, fmt.Errorf("can't mix constants types in arrays: `%s` is not of type int", item)
				}
				evaluator.AppendValues(itemEval.Value)
			}
			return &evaluator, array.Pos, nil
		case reflect.TypeOf(&StringEvaluator{}):
			var evaluator StringValuesEvaluator
			for _, item := range array.Idents {
				itemEval, ok := opts.Constants[item].(*StringEvaluator)
				if !ok {
					return nil, array.Pos, fmt.Errorf("can't mix constants types in arrays: `%s` is not of type string", item)
				}
				evaluator.AppendMembers(ast.StringMember{String: &itemEval.Value})
			}
			return &evaluator, array.Pos, nil
		case reflect.TypeOf(&BoolEvaluator{}):
			var evaluator BoolArrayEvaluator
			for _, item := range array.Idents {
				itemEval, ok := opts.Constants[item].(*BoolEvaluator)
				if !ok {
					return nil, array.Pos, fmt.Errorf("can't mix constants types in arrays: `%s` is not of type bool", item)
				}
				evaluator.AppendValues(itemEval.Value)
			}
			return &evaluator, array.Pos, nil
		}
		return nil, array.Pos, fmt.Errorf("array of unsupported identifiers (ident type: `%s`)", reflect.TypeOf(opts.Constants[array.Idents[0]]))
	} else if array.Variable != nil {
		varName, ok := isVariableName(*array.Variable)
		if !ok {
			return nil, array.Pos, NewError(array.Pos, "invalid variable name '%s'", *array.Variable)
		}
		return evaluatorFromVariable(varName, array.Pos, opts)
	} else if array.CIDR != nil {
		var values CIDRValues
		if err := values.AppendCIDR(*array.CIDR); err != nil {
			return nil, array.Pos, NewError(array.Pos, "invalid CIDR '%s'", *array.CIDR)
		}

		evaluator := &CIDRValuesEvaluator{
			Value:     values,
			ValueType: IPNetValueType,
			Offset:    array.Pos.Offset,
		}
		return evaluator, array.Pos, nil
	} else if len(array.CIDRMembers) != 0 {
		var values CIDRValues
		for _, member := range array.CIDRMembers {
			if member.CIDR != nil {
				if err := values.AppendCIDR(*member.CIDR); err != nil {
					return nil, array.Pos, NewError(array.Pos, "invalid CIDR '%s'", *member.CIDR)
				}
			} else if member.IP != nil {
				if err := values.AppendIP(*member.IP); err != nil {
					return nil, array.Pos, NewError(array.Pos, "invalid IP '%s'", *member.IP)
				}
			}
		}

		evaluator := &CIDRValuesEvaluator{
			Value:     values,
			ValueType: IPNetValueType,
			Offset:    array.Pos.Offset,
		}
		return evaluator, array.Pos, nil
	}

	return nil, array.Pos, NewError(array.Pos, "unknown array element type")
}

func isVariableName(str string) (string, bool) {
	if strings.HasPrefix(str, "${") && strings.HasSuffix(str, "}") {
		return str[2 : len(str)-1], true
	}
	return "", false
}

func evaluatorFromVariable(varname string, pos lexer.Position, opts *Opts) (interface{}, lexer.Position, error) {
	var variableEvaluator interface{}
	variable := opts.VariableStore.Get(varname)
	if variable != nil {
		return variable.GetEvaluator(), pos, nil
	}

	if strings.HasSuffix(varname, ".length") {
		trimmedVariable := strings.TrimSuffix(varname, ".length")
		if variable = opts.VariableStore.Get(trimmedVariable); variable != nil {
			variableEvaluator = variable.GetEvaluator()
			switch evaluator := variableEvaluator.(type) {
			case *StringArrayEvaluator:
				return &IntEvaluator{
					EvalFnc: func(ctx *Context) int {
						v := evaluator.Eval(ctx)
						return len(v.([]string))
					},
				}, pos, nil
			case *StringEvaluator:
				return &IntEvaluator{
					EvalFnc: func(ctx *Context) int {
						v := evaluator.Eval(ctx)
						return len(v.(string))
					},
				}, pos, nil
			case *IntArrayEvaluator:
				return &IntEvaluator{
					EvalFnc: func(ctx *Context) int {
						v := evaluator.Eval(ctx)
						return len(v.([]int))
					},
				}, pos, nil
			case *CIDRArrayEvaluator:
				return &IntEvaluator{
					EvalFnc: func(ctx *Context) int {
						v := evaluator.Eval(ctx)
						return len(v.([]net.IPNet))
					},
				}, pos, nil
			default:
				return nil, pos, NewError(pos, "'length' cannot be used on '%s'", trimmedVariable)
			}
		}

	}

	return nil, pos, NewError(pos, "variable '%s' doesn't exist", varname)
}

func stringEvaluatorFromVariable(str string, pos lexer.Position, opts *Opts) (interface{}, lexer.Position, error) {
	var evaluators []*StringEvaluator

	doLoc := func(sub string) error {
		if varname, ok := isVariableName(sub); ok {
			evaluator, pos, err := evaluatorFromVariable(varname, pos, opts)
			if err != nil {
				return err
			}

			switch evaluator := evaluator.(type) {
			case *StringArrayEvaluator:
				evaluators = append(evaluators, &StringEvaluator{
					EvalFnc: func(ctx *Context) string {
						return strings.Join(evaluator.EvalFnc(ctx), ",")
					}})
			case *IntArrayEvaluator:
				evaluators = append(evaluators, &StringEvaluator{
					EvalFnc: func(ctx *Context) string {
						var result string
						for i, number := range evaluator.EvalFnc(ctx) {
							if i != 0 {
								result += ","
							}
							result += strconv.FormatInt(int64(number), 10)
						}
						return result
					}})
			case *StringEvaluator:
				evaluators = append(evaluators, evaluator)
			case *IntEvaluator:
				evaluators = append(evaluators, &StringEvaluator{
					EvalFnc: func(ctx *Context) string {
						return strconv.FormatInt(int64(evaluator.EvalFnc(ctx)), 10)
					}})
			default:
				return NewError(pos, "variable type not supported '%s'", varname)
			}
		} else {
			evaluators = append(evaluators, &StringEvaluator{Value: sub})
		}

		return nil
	}

	var last int
	for _, loc := range variableRegex.FindAllIndex([]byte(str), -1) {
		if loc[0] > 0 {
			if err := doLoc(str[last:loc[0]]); err != nil {
				return nil, pos, err
			}
		}
		if err := doLoc(str[loc[0]:loc[1]]); err != nil {
			return nil, pos, err
		}
		last = loc[1]
	}
	if last < len(str) {
		if err := doLoc(str[last:]); err != nil {
			return nil, pos, err
		}
	}

	return &StringEvaluator{
		Value:     str,
		ValueType: VariableValueType,
		EvalFnc: func(ctx *Context) string {
			var result string
			for _, evaluator := range evaluators {
				if evaluator.EvalFnc != nil {
					result += evaluator.EvalFnc(ctx)
				} else {
					result += evaluator.Value
				}
			}
			return result
		},
	}, pos, nil
}

// StringEqualsWrapper makes use of operator overrides
func StringEqualsWrapper(a *StringEvaluator, b *StringEvaluator, state *State) (*BoolEvaluator, error) {
	var evaluator *BoolEvaluator
	var err error

	if a.OpOverrides != nil && a.OpOverrides.StringEquals != nil {
		evaluator, err = a.OpOverrides.StringEquals(a, b, state)
	} else if b.OpOverrides != nil && b.OpOverrides.StringEquals != nil {
		evaluator, err = b.OpOverrides.StringEquals(a, b, state)
	} else {
		evaluator, err = StringEquals(a, b, state)
	}
	if err != nil {
		return nil, err
	}

	return evaluator, nil
}

// StringArrayContainsWrapper makes use of operator overrides
func StringArrayContainsWrapper(a *StringEvaluator, b *StringArrayEvaluator, state *State) (*BoolEvaluator, error) {
	var evaluator *BoolEvaluator
	var err error

	if a.OpOverrides != nil && a.OpOverrides.StringArrayContains != nil {
		evaluator, err = a.OpOverrides.StringArrayContains(a, b, state)
	} else if b.OpOverrides != nil && b.OpOverrides.StringArrayContains != nil {
		evaluator, err = b.OpOverrides.StringArrayContains(a, b, state)
	} else {
		evaluator, err = StringArrayContains(a, b, state)
	}
	if err != nil {
		return nil, err
	}

	return evaluator, nil
}

// stringValuesContainsWrapper makes use of operator overrides
func stringValuesContainsWrapper(a *StringEvaluator, b *StringValuesEvaluator, state *State) (*BoolEvaluator, error) {
	var evaluator *BoolEvaluator
	var err error

	if a.OpOverrides != nil && a.OpOverrides.StringValuesContains != nil {
		evaluator, err = a.OpOverrides.StringValuesContains(a, b, state)
	} else {
		evaluator, err = StringValuesContains(a, b, state)
	}
	if err != nil {
		return nil, err
	}

	return evaluator, nil
}

// stringArrayMatchesWrapper makes use of operator overrides
func stringArrayMatchesWrapper(a *StringArrayEvaluator, b *StringValuesEvaluator, state *State) (*BoolEvaluator, error) {
	var evaluator *BoolEvaluator
	var err error

	if a.OpOverrides != nil && a.OpOverrides.StringArrayMatches != nil {
		evaluator, err = a.OpOverrides.StringArrayMatches(a, b, state)
	} else {
		evaluator, err = StringArrayMatches(a, b, state)
	}
	if err != nil {
		return nil, err
	}

	return evaluator, nil
}

// NodeToEvaluator converts an AST expression to an evaluator
func NodeToEvaluator(obj interface{}, opts *Opts, state *State) (interface{}, lexer.Position, error) {
	return nodeToEvaluator(obj, opts, state)
}

func nodeToEvaluator(obj interface{}, opts *Opts, state *State) (interface{}, lexer.Position, error) {
	var err error
	var boolEvaluator *BoolEvaluator
	var pos lexer.Position
	var cmp, unary, next interface{}

	switch obj := obj.(type) {
	case *ast.BooleanExpression:
		return nodeToEvaluator(obj.Expression, opts, state)
	case *ast.Expression:
		cmp, pos, err = nodeToEvaluator(obj.Comparison, opts, state)
		if err != nil {
			return nil, pos, err
		}

		if obj.Op != nil {
			cmpBool, ok := cmp.(*BoolEvaluator)
			if !ok {
				return nil, obj.Pos, NewTypeError(obj.Pos, reflect.Bool)
			}

			next, pos, err = nodeToEvaluator(obj.Next, opts, state)
			if err != nil {
				return nil, pos, err
			}

			nextBool, ok := next.(*BoolEvaluator)
			if !ok {
				return nil, pos, NewTypeError(pos, reflect.Bool)
			}

			switch *obj.Op {
			case "||", "or":
				boolEvaluator, err = Or(cmpBool, nextBool, state)
				if err != nil {
					return nil, obj.Pos, err
				}
				return boolEvaluator, obj.Pos, nil
			case "&&", "and":
				boolEvaluator, err = And(cmpBool, nextBool, state)
				if err != nil {
					return nil, obj.Pos, err
				}
				return boolEvaluator, obj.Pos, nil
			}
			return nil, pos, NewOpUnknownError(obj.Pos, *obj.Op)
		}
		return cmp, obj.Pos, nil
	case *ast.BitOperation:
		unary, pos, err = nodeToEvaluator(obj.Unary, opts, state)
		if err != nil {
			return nil, pos, err
		}

		if obj.Op != nil {
			bitInt, ok := unary.(*IntEvaluator)
			if !ok {
				return nil, obj.Pos, NewTypeError(obj.Pos, reflect.Int)
			}

			next, pos, err = nodeToEvaluator(obj.Next, opts, state)
			if err != nil {
				return nil, pos, err
			}

			nextInt, ok := next.(*IntEvaluator)
			if !ok {
				return nil, pos, NewTypeError(pos, reflect.Int)
			}

			switch *obj.Op {
			case "&":
				intEvaluator, err := IntAnd(bitInt, nextInt, state)
				if err != nil {
					return nil, pos, err
				}
				return intEvaluator, obj.Pos, nil
			case "|":
				IntEvaluator, err := IntOr(bitInt, nextInt, state)
				if err != nil {
					return nil, pos, err
				}
				return IntEvaluator, obj.Pos, nil
			case "^":
				IntEvaluator, err := IntXor(bitInt, nextInt, state)
				if err != nil {
					return nil, pos, err
				}
				return IntEvaluator, obj.Pos, nil
			}
			return nil, pos, NewOpUnknownError(obj.Pos, *obj.Op)
		}
		return unary, obj.Pos, nil

	case *ast.ArithmeticOperation:
		// Process the first operand
		first, pos, err := nodeToEvaluator(obj.First, opts, state)
		if err != nil {
			return nil, pos, err
		}

		// If it's just one element (is a bitoperation: maybe a string, an int ....)
		if len(obj.Rest) == 0 {
			return first, obj.Pos, nil
		}

		// Else it's an operation, so it must be an int
		currInt, ok := first.(*IntEvaluator)
		if !ok {
			return nil, obj.Pos, NewTypeError(obj.Pos, reflect.Int)
		}

		// Process the remaining operations and operands
		for _, arithElem := range obj.Rest {
			// Handle the operand
			operand, pos, err := nodeToEvaluator(arithElem.Operand, opts, state)
			if err != nil {
				return nil, pos, err
			}
			operandInt, ok := operand.(*IntEvaluator)
			if !ok {
				return nil, pos, NewTypeError(pos, reflect.Int)
			}

			// Perform the operation on the current and next operands
			switch arithElem.Op {
			case "+":
				currInt, err = IntPlus(currInt, operandInt, state)
				if err != nil {
					return nil, pos, err
				}

			case "-":
				currInt, err = IntMinus(currInt, operandInt, state)
				if err != nil {
					return nil, pos, err
				}
			}
		}

		// Return the final result after processing all operations and operands
		currInt.isFromArithmeticOperation = true
		return currInt, obj.Pos, nil

	case *ast.Comparison:
		unary, pos, err = nodeToEvaluator(obj.ArithmeticOperation, opts, state)
		if err != nil {
			return nil, pos, err
		}

		if obj.ArrayComparison != nil {
			next, pos, err = nodeToEvaluator(obj.ArrayComparison, opts, state)
			if err != nil {
				return nil, pos, err
			}

			switch unary := unary.(type) {
			case *BoolEvaluator:
				switch nextBool := next.(type) {
				case *BoolArrayEvaluator:
					boolEvaluator, err = ArrayBoolContains(unary, nextBool, state)
					if err != nil {
						return nil, pos, err
					}
					if *obj.ArrayComparison.Op == "notin" {
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return boolEvaluator, obj.Pos, nil
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.Bool)
				}
			case *StringEvaluator:
				switch nextString := next.(type) {
				case *StringArrayEvaluator:
					boolEvaluator, err = StringArrayContainsWrapper(unary, nextString, state)
					if err != nil {
						return nil, pos, err
					}
				case *StringValuesEvaluator:
					boolEvaluator, err = stringValuesContainsWrapper(unary, nextString, state)
					if err != nil {
						return nil, pos, err
					}
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.String)
				}
				if *obj.ArrayComparison.Op == "notin" {
					return Not(boolEvaluator, state), obj.Pos, nil
				}
				return boolEvaluator, obj.Pos, nil
			case *StringValuesEvaluator:
				switch nextStringArray := next.(type) {
				case *StringArrayEvaluator:
					boolEvaluator, err = stringArrayMatchesWrapper(nextStringArray, unary, state)
					if err != nil {
						return nil, pos, err
					}
					if *obj.ArrayComparison.Op == "notin" {
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return boolEvaluator, obj.Pos, nil
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.String)
				}
			case *StringArrayEvaluator:
				switch nextStringArray := next.(type) {
				case *StringValuesEvaluator:
					boolEvaluator, err = stringArrayMatchesWrapper(unary, nextStringArray, state)
					if err != nil {
						return nil, pos, err
					}
					if *obj.ArrayComparison.Op == "notin" {
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return boolEvaluator, obj.Pos, nil
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.String)
				}
			case *IntEvaluator:
				switch nextInt := next.(type) {
				case *IntArrayEvaluator:
					boolEvaluator, err = IntArrayEquals(unary, nextInt, state)
					if err != nil {
						return nil, pos, err
					}
					if *obj.ArrayComparison.Op == "notin" {
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return boolEvaluator, obj.Pos, nil
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.Int)
				}
			case *IntArrayEvaluator:
				switch nextIntArray := next.(type) {
				case *IntArrayEvaluator:
					boolEvaluator, err = IntArrayMatches(unary, nextIntArray, state)
					if err != nil {
						return nil, pos, err
					}
					if *obj.ArrayComparison.Op == "notin" {
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return boolEvaluator, obj.Pos, nil
				default:
					return nil, pos, NewArrayTypeError(pos, reflect.Array, reflect.Int)
				}
			case *CIDREvaluator:
				switch nextCIDR := next.(type) {
				case *CIDREvaluator:
					nextIP, ok := next.(*CIDREvaluator)
					if !ok {
						return nil, pos, NewTypeError(pos, reflect.TypeOf(CIDREvaluator{}).Kind())
					}

					boolEvaluator, err = CIDREquals(unary, nextIP, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					switch *obj.ArrayComparison.Op {
					case "in", "allin":
						return boolEvaluator, obj.Pos, nil
					case "notin":
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				case *CIDRValuesEvaluator:
					switch *obj.ArrayComparison.Op {
					case "in", "allin":
						boolEvaluator, err = CIDRValuesContains(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "notin":
						boolEvaluator, err = CIDRValuesContains(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				case *CIDRArrayEvaluator:
					switch *obj.ArrayComparison.Op {
					case "in", "allin":
						boolEvaluator, err = CIDRArrayContains(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "notin":
						boolEvaluator, err = CIDRArrayContains(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				default:
					return nil, pos, NewCIDRTypeError(pos, reflect.Array, next)
				}
			case *CIDRArrayEvaluator:
				switch nextCIDR := next.(type) {
				case *CIDRValuesEvaluator:
					switch *obj.ArrayComparison.Op {
					case "in":
						boolEvaluator, err = CIDRArrayMatches(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "allin":
						boolEvaluator, err = CIDRArrayMatchesAll(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "notin":
						boolEvaluator, err = CIDRArrayMatches(unary, nextCIDR, state)
						if err != nil {
							return nil, pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				default:
					return nil, pos, NewCIDRTypeError(pos, reflect.Array, next)
				}
			case *CIDRValuesEvaluator:
				switch nextCIDR := next.(type) {
				case *CIDREvaluator:
					switch *obj.ArrayComparison.Op {
					case "in", "allin":
						boolEvaluator, err = CIDRValuesContains(nextCIDR, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "notin":
						boolEvaluator, err = CIDRValuesContains(nextCIDR, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				case *CIDRArrayEvaluator:
					switch *obj.ArrayComparison.Op {
					case "allin":
						boolEvaluator, err = CIDRArrayMatchesAll(nextCIDR, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "in":
						boolEvaluator, err = CIDRArrayMatches(nextCIDR, unary, state)
						if err != nil {
							return nil, pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "notin":
						boolEvaluator, err = CIDRArrayMatches(nextCIDR, unary, state)
						if err != nil {
							return nil, pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)
				default:
					return nil, pos, NewCIDRTypeError(pos, reflect.Array, next)
				}
			default:
				return nil, pos, NewTypeError(pos, reflect.Array)
			}
		} else if obj.ScalarComparison != nil {
			next, pos, err = nodeToEvaluator(obj.ScalarComparison, opts, state)
			if err != nil {
				return nil, pos, err
			}

			switch unary := unary.(type) {
			case *BoolEvaluator:
				nextBool, ok := next.(*BoolEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Bool)
				}

				switch *obj.ScalarComparison.Op {
				case "!=":
					boolEvaluator, err = BoolEquals(unary, nextBool, state)
					if err != nil {
						return nil, pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "==":
					boolEvaluator, err = BoolEquals(unary, nextBool, state)
					if err != nil {
						return nil, pos, err
					}
					return boolEvaluator, obj.Pos, nil
				}
				return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
			case *BoolArrayEvaluator:
				nextBool, ok := next.(*BoolEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Bool)
				}

				switch *obj.ScalarComparison.Op {
				case "!=":
					boolEvaluator, err = BoolArrayEquals(nextBool, unary, state)
					if err != nil {
						return nil, pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "==":
					boolEvaluator, err = BoolArrayEquals(nextBool, unary, state)
					if err != nil {
						return nil, pos, err
					}
					return boolEvaluator, obj.Pos, nil
				}
				return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
			case *StringEvaluator:
				nextString, ok := next.(*StringEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.String)
				}

				switch *obj.ScalarComparison.Op {
				case "!=":
					boolEvaluator, err = StringEqualsWrapper(unary, nextString, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "!~":
					if nextString.EvalFnc != nil {
						return nil, obj.Pos, &ErrNonStaticPattern{Field: nextString.Field}
					}

					// force pattern if needed
					if nextString.ValueType == ScalarValueType {
						nextString.ValueType = PatternValueType
					}

					boolEvaluator, err = StringEqualsWrapper(unary, nextString, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "==":
					boolEvaluator, err = StringEqualsWrapper(unary, nextString, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return boolEvaluator, obj.Pos, nil
				case "=~":
					if nextString.EvalFnc != nil {
						return nil, obj.Pos, &ErrNonStaticPattern{Field: nextString.Field}
					}

					// force pattern if needed
					if nextString.ValueType == ScalarValueType {
						nextString.ValueType = PatternValueType
					}

					boolEvaluator, err = StringEqualsWrapper(unary, nextString, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return boolEvaluator, obj.Pos, nil
				}
				return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
			case *CIDREvaluator:
				switch nextIP := next.(type) {
				case *CIDREvaluator:
					switch *obj.ScalarComparison.Op {
					case "!=":
						boolEvaluator, err = CIDREquals(unary, nextIP, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					case "==":
						boolEvaluator, err = CIDREquals(unary, nextIP, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
				}

			case *CIDRArrayEvaluator:
				cidrEvaluator, ok := next.(*CIDREvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.String)
				}

				switch *obj.ScalarComparison.Op {
				case "!=":
					boolEvaluator, err = CIDRArrayMatchesCIDREvaluator(unary, cidrEvaluator, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "==":
					boolEvaluator, err = CIDRArrayMatchesCIDREvaluator(unary, cidrEvaluator, state)
					if err != nil {
						return nil, pos, err
					}
					return boolEvaluator, obj.Pos, nil
				}

				return nil, pos, NewOpUnknownError(obj.Pos, *obj.ArrayComparison.Op)

			case *StringArrayEvaluator:
				nextString, ok := next.(*StringEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.String)
				}

				switch *obj.ScalarComparison.Op {
				case "!=":
					boolEvaluator, err = StringArrayContainsWrapper(nextString, unary, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "==":
					boolEvaluator, err = StringArrayContainsWrapper(nextString, unary, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return boolEvaluator, obj.Pos, nil
				case "!~":
					if nextString.EvalFnc != nil {
						return nil, obj.Pos, &ErrNonStaticPattern{Field: nextString.Field}
					}

					// force pattern if needed
					if nextString.ValueType == ScalarValueType {
						nextString.ValueType = PatternValueType
					}

					boolEvaluator, err = StringArrayContainsWrapper(nextString, unary, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return Not(boolEvaluator, state), obj.Pos, nil
				case "=~":
					if nextString.EvalFnc != nil {
						return nil, obj.Pos, &ErrNonStaticPattern{Field: nextString.Field}
					}

					// force pattern if needed
					if nextString.ValueType == ScalarValueType {
						nextString.ValueType = PatternValueType
					}

					boolEvaluator, err = StringArrayContainsWrapper(nextString, unary, state)
					if err != nil {
						return nil, obj.Pos, err
					}
					return boolEvaluator, obj.Pos, nil
				}
			case *IntEvaluator:
				switch nextInt := next.(type) {
				case *IntEvaluator:
					if nextInt.isDuration {
						if unary.isFromArithmeticOperation {
							switch *obj.ScalarComparison.Op {
							case "<":
								boolEvaluator, err = DurationLesserThanArithmeticOperation(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case "<=":
								boolEvaluator, err = DurationLesserOrEqualThanArithmeticOperation(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case ">":
								boolEvaluator, err = DurationGreaterThanArithmeticOperation(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case ">=":
								boolEvaluator, err = DurationGreaterOrEqualThanArithmeticOperation(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case "==":
								boolEvaluator, err = DurationEqualArithmeticOperation(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							}

						} else {
							switch *obj.ScalarComparison.Op {
							case "<":
								boolEvaluator, err = DurationLesserThan(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case "<=":
								boolEvaluator, err = DurationLesserOrEqualThan(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case ">":
								boolEvaluator, err = DurationGreaterThan(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case ">=":
								boolEvaluator, err = DurationGreaterOrEqualThan(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							case "==":
								boolEvaluator, err = DurationEqual(unary, nextInt, state)
								if err != nil {
									return nil, obj.Pos, err
								}
								return boolEvaluator, obj.Pos, nil
							}
						}
					} else {
						switch *obj.ScalarComparison.Op {
						case "<":
							boolEvaluator, err = LesserThan(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}
							return boolEvaluator, obj.Pos, nil
						case "<=":
							boolEvaluator, err = LesserOrEqualThan(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}
							return boolEvaluator, obj.Pos, nil
						case ">":
							boolEvaluator, err = GreaterThan(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}
							return boolEvaluator, obj.Pos, nil
						case ">=":
							boolEvaluator, err = GreaterOrEqualThan(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}
							return boolEvaluator, obj.Pos, nil
						case "!=":
							boolEvaluator, err = IntEquals(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}

							return Not(boolEvaluator, state), obj.Pos, nil
						case "==":
							boolEvaluator, err = IntEquals(unary, nextInt, state)
							if err != nil {
								return nil, obj.Pos, err
							}
							return boolEvaluator, obj.Pos, nil
						default:
							return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
						}
					}
				case *IntArrayEvaluator:
					nextIntArray := next.(*IntArrayEvaluator)

					switch *obj.ScalarComparison.Op {
					case "<":
						boolEvaluator, err = IntArrayLesserThan(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "<=":
						boolEvaluator, err = IntArrayLesserOrEqualThan(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">":
						boolEvaluator, err = IntArrayGreaterThan(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">=":
						boolEvaluator, err = IntArrayGreaterOrEqualThan(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "!=":
						boolEvaluator, err = IntArrayEquals(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					case "==":
						boolEvaluator, err = IntArrayEquals(unary, nextIntArray, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					default:
						return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
					}
				}
				return nil, pos, NewTypeError(pos, reflect.Int)
			case *IntArrayEvaluator:
				nextInt, ok := next.(*IntEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Int)
				}

				if nextInt.isDuration {
					switch *obj.ScalarComparison.Op {
					case "<":
						boolEvaluator, err = DurationArrayLesserThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "<=":
						boolEvaluator, err = DurationArrayLesserOrEqualThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">":
						boolEvaluator, err = DurationArrayGreaterThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">=":
						boolEvaluator, err = DurationArrayGreaterOrEqualThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					}
				} else {
					switch *obj.ScalarComparison.Op {
					case "<":
						boolEvaluator, err = IntArrayGreaterThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "<=":
						boolEvaluator, err = IntArrayGreaterOrEqualThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">":
						boolEvaluator, err = IntArrayLesserThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case ">=":
						boolEvaluator, err = IntArrayLesserOrEqualThan(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					case "!=":
						boolEvaluator, err = IntArrayEquals(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return Not(boolEvaluator, state), obj.Pos, nil
					case "==":
						boolEvaluator, err = IntArrayEquals(nextInt, unary, state)
						if err != nil {
							return nil, obj.Pos, err
						}
						return boolEvaluator, obj.Pos, nil
					}
					return nil, pos, NewOpUnknownError(obj.Pos, *obj.ScalarComparison.Op)
				}
			}
		} else {
			return unary, pos, nil
		}

	case *ast.ArrayComparison:
		return nodeToEvaluator(obj.Array, opts, state)

	case *ast.ScalarComparison:
		return nodeToEvaluator(obj.Next, opts, state)

	case *ast.Unary:
		if obj.Op != nil {
			unary, pos, err = nodeToEvaluator(obj.Unary, opts, state)
			if err != nil {
				return nil, pos, err
			}

			switch *obj.Op {
			case "!", "not":
				unaryBool, ok := unary.(*BoolEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Bool)
				}

				return Not(unaryBool, state), obj.Pos, nil
			case "-":
				unaryInt, ok := unary.(*IntEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Int)
				}

				return Minus(unaryInt, state), pos, nil
			case "^":
				unaryInt, ok := unary.(*IntEvaluator)
				if !ok {
					return nil, pos, NewTypeError(pos, reflect.Int)
				}

				return IntNot(unaryInt, state), pos, nil
			}
			return nil, pos, NewOpUnknownError(obj.Pos, *obj.Op)
		}

		return nodeToEvaluator(obj.Primary, opts, state)
	case *ast.Primary:
		switch {
		case obj.Ident != nil:
			return identToEvaluator(&ident{Pos: obj.Pos, Ident: obj.Ident}, opts, state)
		case obj.Number != nil:
			return &IntEvaluator{
				Value:  *obj.Number,
				Offset: obj.Pos.Offset,
			}, obj.Pos, nil
		case obj.Variable != nil:
			varname, ok := isVariableName(*obj.Variable)
			if !ok {
				return nil, obj.Pos, NewError(obj.Pos, "internal variable error '%s'", varname)
			}

			return evaluatorFromVariable(varname, obj.Pos, opts)
		case obj.Duration != nil:
			return &IntEvaluator{
				Value:      *obj.Duration,
				Offset:     obj.Pos.Offset,
				isDuration: true,
			}, obj.Pos, nil
		case obj.String != nil:
			str := *obj.String

			// contains variables
			if len(variableRegex.FindAllIndex([]byte(str), -1)) > 0 {
				return stringEvaluatorFromVariable(str, obj.Pos, opts)
			}

			return &StringEvaluator{
				Value:     str,
				ValueType: ScalarValueType,
				Offset:    obj.Pos.Offset,
			}, obj.Pos, nil
		case obj.Pattern != nil:
			evaluator := &StringEvaluator{
				Value:     *obj.Pattern,
				ValueType: PatternValueType,
				Weight:    PatternWeight,
				Offset:    obj.Pos.Offset,
			}
			return evaluator, obj.Pos, nil
		case obj.Regexp != nil:
			evaluator := &StringEvaluator{
				Value:     *obj.Regexp,
				ValueType: RegexpValueType,
				Weight:    RegexpWeight,
				Offset:    obj.Pos.Offset,
			}
			return evaluator, obj.Pos, nil
		case obj.IP != nil:
			ipnet, err := ParseCIDR(*obj.IP)
			if err != nil {
				return nil, obj.Pos, NewError(obj.Pos, "invalid IP '%s'", *obj.IP)
			}

			evaluator := &CIDREvaluator{
				Value:     *ipnet,
				ValueType: IPNetValueType,
				Offset:    obj.Pos.Offset,
			}
			return evaluator, obj.Pos, nil
		case obj.CIDR != nil:
			ipnet, err := ParseCIDR(*obj.CIDR)
			if err != nil {
				return nil, obj.Pos, NewError(obj.Pos, "invalid CIDR '%s'", *obj.CIDR)
			}

			evaluator := &CIDREvaluator{
				Value:     *ipnet,
				ValueType: IPNetValueType,
				Offset:    obj.Pos.Offset,
			}
			return evaluator, obj.Pos, nil
		case obj.SubExpression != nil:
			return nodeToEvaluator(obj.SubExpression, opts, state)
		default:
			return nil, obj.Pos, NewError(obj.Pos, "unknown primary '%s'", reflect.TypeOf(obj))
		}
	case *ast.Array:
		return arrayToEvaluator(obj, opts, state)
	}

	return nil, lexer.Position{}, NewError(lexer.Position{}, "unknown entity '%s'", reflect.TypeOf(obj))
}
