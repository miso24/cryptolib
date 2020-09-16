import gmpy2


def fermat_factor(n):
    """

    Fermat's factorization method

    Args:
        n (int): target

    Returns:
        int: factor

    References:
        - https://www.geeksforgeeks.org/fermats-factorization-method
        - https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
    """
    if gmpy2.is_square(n):
        tmp = int(gmpy2.isqrt(n))
        return tmp

    a = gmpy2.isqrt(n)
    b = a ** 2 - n
    while not gmpy2.is_square(b):
        b += 2 * a + 1
        a += 1
    b_sqrt = gmpy2.isqrt(b)
    return int(a - b_sqrt)
