#pragma once

#include <type_traits>
#include <tuple>

// primary fallback template
template <typename T>
struct function_traits {
    static_assert(std::is_function<T>::value == false, "function_traits: not recognised as a function pointer");
};


// Partial Specialisation for __cdecl
template <typename Ret, typename... Args>
struct function_traits<Ret(__cdecl*)(Args...)>
{
    using pointer_type = Ret(__cdecl*)(Args...);
    using return_type = Ret;
    static constexpr std::size_t arity = sizeof...(Args);

    // access each argument type via arg<index>
    template <std::size_t Index>
    using argument_tuple = std::tuple<Args...>;
    using arg = std::tuple_element_t<Index, argument_tuple>;

};

// Partial Specialisation for __stdcall
template <typename Ret, typename... Args>
struct function_traits<Ret(__stdcall*)(Args...)>
{
    using pointer_type = Ret(__stdcall*)(Args...);
    using return_type = Ret;
    static constexpr std::size_t arity = sizeof...(Args);

    // access each argument type via arg<index>
    using argument_tuple = std::tuple<Args...>;
    template <std::size_t Index>
    using arg = std::tuple_element_t<Index, argument_tuple>;
};

template <typename T>
struct function_info
{
    const char* name;
    using traits = function_traits<T>;
};