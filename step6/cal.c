#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <math.h>
#include "cal.h"
// Function to evaluate an arithmetic expression
double evaluate_expression(const char** expression) {
    double value = parse_term(expression);
    while (**expression) {
        if (**expression == '+') {
            (*expression)++;
            value += parse_term(expression);
        } else if (**expression == '-') {
            (*expression)++;
            value -= parse_term(expression);
        } else {
            break;
        }
    }
    return value;
}

// Function to parse a term (handles *, /, and ^)
double parse_term(const char** expression) {
    double value = parse_factor(expression);
    while (**expression) {
        if (**expression == '*') {
            (*expression)++;
            value *= parse_factor(expression);
        } else if (**expression == '/') {
            (*expression)++;
            value /= parse_factor(expression);
        } else {
            break;
        }
    }
    return value;
}

// Function to parse a factor (handles ^ for exponentiation)
double parse_factor(const char** expression) {
    double value = parse_primary(expression);
    while (**expression) {
        if (**expression == '^') {
            (*expression)++;
            value = pow(value, parse_factor(expression));
        } else {
            break;
        }
    }
    return value;
}

// Function to parse primary expressions (numbers, parentheses, and square root)
double parse_primary(const char** expression) {
    double value;
    if (**expression == '(') {
        (*expression)++;  // Skip '('
        value = evaluate_expression(expression);
        while (**expression && **expression != ')') {
            (*expression)++;
        }
        if (**expression == ')') {
            (*expression)++;  // Skip ')'
        }
    } else if (strncmp(*expression, "sqrt(", 5) == 0) {
        (*expression) += 5;  // Skip 'sqrt('
        value = sqrt(evaluate_expression(expression));
        while (**expression && **expression != ')') {
            (*expression)++;
        }
        if (**expression == ')') {
            (*expression)++;  // Skip ')'
        }
    } else {
        char* end;
        value = strtod(*expression, &end);
        *expression = end;
    }
    return value;
}
