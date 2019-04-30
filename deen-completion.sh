#/usr/bin/env bash

_deen_completions()
{
  local NPO_SCRIPT="$(whereis -b deen | cut -d ' ' -f 2)"
  if [ -h "$NPO_SCRIPT" ]; then
    local NPO_SCRIPT="$(readlink "$NPO_SCRIPT")"
  fi
  
  if [ -n "$ZSH_VERSION" ]; then
    # ZSH
    local COMP0="${COMP_WORDS[0]}"
    local COMP1="${COMP_WORDS[1]}"
  elif [ -n "$BASH_VERSION" ]; then
    # Bash
    local COMP0="${COMP_WORDS[1]}"
    local COMP1="${COMP_WORDS[2]}"
  else
    echo "unsupported shell"
  fi

  local completions="$(deen -l -v)"
  if [ "${COMP_CWORD}" = "1" ]; then
    COMPREPLY=($(compgen -W "$completions" -- "$COMP0"))
  elif [ "${COMP_CWORD}" = "2" ]; then
    COMPREPLY=($(compgen -W "$completions" -- "$COMP1"))
  fi
}

complete -F _deen_completions deen