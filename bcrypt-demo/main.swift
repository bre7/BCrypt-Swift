import Foundation

let tests = [
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW" : "U*U",
    "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK" : "U*U*",
    "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a" : "U*U*U",
    "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui" :
        "0123456789abcdefghijklmnopqrstuvwxyz" +
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" +
    "chars after 72 are ignored",
    "$2a$04$TI13sbmh3IHnmRepeEFoJOkVZWsn5S1O8QOwm8ZU5gNIpJog9pXZm" : "vapor",
    "$2a$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s." : "",
    "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe" : "a",
    "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i" : "abc",
    "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC" : "abcdefghijklmnopqrstuvwxyz",
    "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO" : "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
]

let bcryptBSD = try BCrypt_BSD(cost: 5)
for test in tests.enumerated() {
    if bcryptBSD.validate(message: test.element.value, hashed: test.element.key) {
        print( "BCrypt_OpenBSD Test #\(test.offset + 1): ✅")
    } else {
        print( "BCrypt_OpenBSD Test #\(test.offset + 1): 🚫")
    }
}

let bcryptOW = try BCrypt_OW(cost: 5)
for test in tests.enumerated() {
    if bcryptOW.validate(message: test.element.value, hashed: test.element.key) {
        print( "BCrypt_OpenWall Test #\(test.offset + 1): ✅")
    } else {
        print( "BCrypt_OpenWall #\(test.offset + 1): 🚫")
    }
}
