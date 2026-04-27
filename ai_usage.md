
Prompts Used:
1. "I have a C struct `Report` for an OS lab. Write a function `int parse_condition(const char *input, char *field, char *op, char *value);` that splits a string like 'severity:>=:2' into its three parts."
2. "Write a function `int match_condition(Report *r, const char *field, const char *op, const char *value);` that checks if the record matches the parsed condition. Cast the value to integer for severity."

**What was generated:**
The AI provided `strtok` logic for parsing and an `if/else` chain using `strcmp` for the operator matching.

**What I changed and why:**
* **Safety:** I added a `strncpy` into a temporary buffer in `parse_condition` because `strtok` modifies the original string in place. If `const char *input` was passed directly, it would cause a segmentation fault.
* **Type Casting:** I ensured `atoi(value)` was used only inside the `if (strcmp(field, "severity") == 0)` block. If it was cast globally, it would fail when matching string fields like `category`.

**What I learned:**
I learned how string tokenization (`strtok`) interacts with memory, and how to programmatically route string-based operators (like `==` and `>=`) into actual C conditional logic. I also learned that AI doesn't always account for memory mutability with `const char*` unless specifically prompted.