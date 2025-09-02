using System.Collections;
using TMPro;
using UnityEngine;
using UnityEngine.Networking;

public class AuthHandler : MonoBehaviour
{
    private string apiUrl = "https://sid-restapi.onrender.com";

    public void Login()
    {
        string username = GameObject.Find("InputFieldUsername").GetComponent<TMP_InputField>().text;
        string password = GameObject.Find("InputFieldPassword").GetComponent<TMP_InputField>().text;
        StartCoroutine(LoginCoroutine(username, password));
    }

    private IEnumerator LoginCoroutine(string username, string password)
    {

        string jsonData = JsonUtility.ToJson(new AuthData { username = username, password = password });

        UnityWebRequest www = UnityWebRequest.Put(apiUrl + "/api/auth/login", jsonData);
        www.method ="POST";
        www.SetRequestHeader("Content-Type", "application/json");


        yield return www.SendWebRequest();

            if (www.result == UnityWebRequest.Result.Success)
            {
                Debug.Log("Login successful");
                Debug.Log(www.downloadHandler.text);
            }
            else
            {
                Debug.LogError("Login failed: " + www.error);
            }
    }
}

class AuthData
{
    public string username;
    public string password;
}

 