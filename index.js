const code = `
def sum(a,b):
    return a+b

test_cases = [
{
'input' : {'a' : 20,'b' : 30},
'output' : 50
},
{
'input' : {'a' : 20,'b' : 20},
'output' : 40
},
{
'input' : {'a' : 10,'b' : -10},
'output' : 0
},
{
'input' : {'a' : 100,'b' : -120},
'output' : -20
},
{
'input' : {'a' : 200,'b' : 300},
'output' : 500
}
]

for i in test_cases:
    ans = sum(i['input']['a'],i['input']['b'])
    print(ans)
`

const fechedData = async () => {
    data = {
        code
    }
    const res = await fetch("http://127.0.0.1:8000/run/",{
        method : "POST",
        headers : {
            "Content-Type" : "application/json"
        },
        body : JSON.stringify(data)
    })

    const resdata = await res.json()
    console.log(resdata)
}

fechedData();