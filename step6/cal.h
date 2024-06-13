#ifndef CAL_H
#define CAL_H
// Function prototypes
double evaluate_expression(const char** expression);
double parse_term(const char** expression);
double parse_factor(const char** expression);
double parse_primary(const char** expression);

#endif
