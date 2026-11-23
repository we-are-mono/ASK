"""The deletion planner of tools/sdk_prune.py, on a small C tree.

What it deletes is what a function's removal takes (definition, the comment
right above it, its EXPORT_SYMBOL, its declarations with their comments, an
#if block left empty), and nothing a live line needs: a call is a use however
it is written, and a function a kept one calls is kept.
"""

import sdk_prune

SOURCE = """\
#include "a.h"

static DEFINE_SPINLOCK(dead_lock);

/* Adds one. */
int dead_one(int x)
{
	return dead_helper(x) + 1;
}
EXPORT_SYMBOL(dead_one);

static int
dead_helper(int x)
{
	return x;
}

int live(int x)
{
	if (x)
		return kept_too(x);
	else
		kept_too(x);
	return kept_caller();
}

#ifdef CONFIG_FOO
int dead_two(void)
{
	return 0;
}
#endif

int kept_too(int x)
{
	return x;
}

int kept_caller(void)
{
	return kept_callee();
}

static int kept_callee(void)
{
	return 1;
}
"""

HEADER = """\
#ifndef A_H
#define A_H
#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************************//**
 @Function      dead_one

 @Description   Adds one.
*//***************************************************************************/
int dead_one(int x);

int kept_too(int x);
int dead_two(void);
int kept_caller(void);

#ifdef __cplusplus
}
#endif
#endif
"""

SOURCE_AFTER = """\
#include "a.h"

int live(int x)
{
	if (x)
		return kept_too(x);
	else
		kept_too(x);
	return kept_caller();
}

int kept_too(int x)
{
	return x;
}

int kept_caller(void)
{
	return kept_callee();
}

static int kept_callee(void)
{
	return 1;
}
"""

HEADER_AFTER = """\
#ifndef A_H
#define A_H
#ifdef __cplusplus
extern "C" {
#endif

int kept_too(int x);
int kept_caller(void);

#ifdef __cplusplus
}
#endif
#endif
"""


def test_removal_takes_what_goes_and_keeps_what_is_used(tmp_path):
    (tmp_path / "a.c").write_text(SOURCE)
    (tmp_path / "a.h").write_text(HEADER)
    names = {"dead_one": None, "dead_two": None, "kept_too": None, "kept_caller": None,
             "dead_helper": ["a.c"], "kept_callee": ["a.c"]}
    plan, uses, review = sdk_prune.plan_removal(tmp_path, names, {"dead_lock": ["a.c"]})
    assert sorted(uses) == ["kept_callee", "kept_caller", "kept_too"], uses
    assert not review
    sdk_prune.apply_plan(tmp_path, plan)
    assert (tmp_path / "a.c").read_text() == SOURCE_AFTER
    assert (tmp_path / "a.h").read_text() == HEADER_AFTER


def test_classification():
    src = sdk_prune.Source("int f(int);\nint g(void)\n{\n\treturn f(1);\n}\n#define H f\n")
    assert src.classify("f", 4)[0] == "decl"
    assert src.classify("g", src.code.index("g("))[0] == "def"
    assert src.classify("f", src.code.index("f(1)"))[0] == "use"
    assert src.classify("f", src.code.rindex("f"))[0] == "use"
    # A ; or brace inside a macro ends no statement: the declaration after it
    # starts on its own line, not inside the macro.
    src = sdk_prune.Source("#define M(x) do { (x); } \\\n\twhile (0)\nint g(void);\n")
    assert src.classify("g", src.code.index("g(")) == ("decl", 3, 3)
