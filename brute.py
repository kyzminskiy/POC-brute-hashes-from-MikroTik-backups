import hashlib

def inverse_mod(a, m):
    """Inverse of a mod m."""
    if a == 0:
        return 0
    return pow(a, -1, m)


def _double(X1, Y1, Z1, p, a):
    """Add a point to itself, arbitrary z."""
    XX = (X1 * X1) % p
    YY = (Y1 * Y1) % p
    YYYY = (YY * YY) % p
    ZZ = (Z1 * Z1) % p

    X1_plus_YY = (X1 + YY) % p
    X1_plus_YY_squared = (X1_plus_YY * X1_plus_YY) % p
    S = (2 * (X1_plus_YY_squared - XX - YYYY)) % p

    a_ZZ_squared = (a * ZZ * ZZ) % p
    M = (3 * XX + a_ZZ_squared) % p

    M_squared = (M * M) % p
    T = (M_squared - 2 * S) % p

    Y3 = (M * (S - T) - 8 * YYYY) % p

    Y1_plus_Z1 = (Y1 + Z1) % p
    Y1_plus_Z1_squared = (Y1_plus_Z1 * Y1_plus_Z1) % p
    Z3 = (Y1_plus_Z1_squared - YY - ZZ) % p

    return T, Y3, Z3


def _add_with_z2_1(X1, Y1, Z1, X2, Y2, p):
    """Add points when Z2 == 1."""
    Z1Z1 = (Z1 * Z1) % p
    U2 = (X2 * Z1Z1) % p
    S2 = (Y2 * Z1Z1 * Z1) % p

    H = (U2 - X1) % p
    HH = (H * H) % p
    I = (4 * HH) % p
    J = (H * I) % p

    r = (2 * (S2 - Y1)) % p
    V = (X1 * I) % p

    X3 = (r * r - J - 2 * V) % p
    Y3 = (r * (V - X3) - 2 * Y1 * J) % p
    Z3 = ((Z1 + H) * (Z1 + H) - Z1Z1 - HH) % p

    return X3, Y3, Z3


def _add(X1, Y1, Z1, X2, Y2, Z2, p):
    """Add two points, select fastest method."""
    if not Y1 or not Z1: return X2, Y2, Z2
    if Z2 == 1: return _add_with_z2_1(X1, Y1, Z1, X2, Y2, p)
    raise NotImplementedError("Addition with Z2 != 1 is not implemented")


def naf(mult):
    """Calculate non-adjacent form of number."""
    ret = []
    while mult:
        if mult & 1:
            nd = mult & 3
            if nd == 3:
                nd = -1
            ret.append(nd)
            mult -= nd
        else:
            ret.append(0)
        mult >>= 1
    return ret


def scale(x, y, z, p):
    """Return point scaled so that z == 1."""
    z_inv = inverse_mod(z, p)
    z_inv2 = (z_inv * z_inv) % p
    x = (x * z_inv2) % p
    y = (y * z_inv2 * z_inv) % p
    return x, y, 1


def point_multiplication(x, y, z, scalar, p, a):
    """Multiply point by an integer."""
    x, y, z = scale(x, y, z, p)
    X2, Y2, _ = x, y, 1
    X3, Y3, Z3 = 0, 0, 1

    naf_digits = naf(scalar)
    for digit in reversed(naf_digits):
        X3, Y3, Z3 = _double(X3, Y3, Z3, p, a)
        if digit != 0:
            Y2_adjusted = Y2 if digit > 0 else -Y2
            X3, Y3, Z3 = _add(X3, Y3, Z3, X2, Y2_adjusted, 1, p)

    return X3, Y3, Z3


def x_coordinate(x, y, z, p):
    """Return affine x coordinate."""
    z_inv = inverse_mod(z, p)
    z_inv2 = (z_inv * z_inv) % p
    return (x * z_inv2) % p


conversion = 38597363079105398474523661669562635951089994888546854679819194669304376384412
curve_a = 19298681539552699237261830834781317975544997444273427339909597334573241639236
curve_p = 57896044618658097711785492504343953926634992332820282019728792003956564819949
x = 19298681539552699237261830834781317975544997444273427339909597334652188435546
y = 43114425171068552920764898935933967039370386198203806730763910166200978582548


def gen_public_key(priv: bytes):
    priv = int.from_bytes(priv, "big")
    X, Y, Z = point_multiplication(x, y, 1, priv, curve_p, curve_a)
    return to_montgomery(X, Y, Z)


def to_montgomery(X, Y, Z):
    X = (x_coordinate(X, Y, Z, curve_p) + conversion) % curve_p
    return int(X).to_bytes(32, "big")


def gen_password_validator_priv(username: str, password: str, salt: bytes):
    return hashlib.sha256(salt + hashlib.sha256((username + ":" + password).encode("utf-8")).digest()).digest()


def read_file(filename):
    with open(filename, 'r') as file:
        return file.readlines()


def write_to_file(filename, data):
    with open(filename, 'w') as file:
        file.writelines(data)


def hex_to_binary(hex_str):
    return bytes.fromhex(hex_str)


def main():
    hashes = read_file('hashes.txt')
    passwords = read_file('pass.txt')

    results = []
    for line in hashes:
        username, salt_hex, v_hex = line.strip().split(':')
        salt = hex_to_binary(salt_hex)
        v = hex_to_binary(v_hex)

        for password in passwords:
            password = password.strip()
            i = gen_password_validator_priv(username, password, salt)
            print('priv:', i.hex())
            x_gamma = gen_public_key(i)
            print('pub:', x_gamma.hex())

            if x_gamma == v:
                results.append(f"{line.strip()}:{password}\n")
                break

    write_to_file('result.txt', results)


if __name__ == "__main__":
    main()
