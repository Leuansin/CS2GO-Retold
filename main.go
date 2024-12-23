package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil" // Para leer datos desde el cuerpo de la respuesta HTTP
	"log"
	"math"
	"net/http" // Para realizar solicitudes HTTP
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"github.com/lxn/win"
	"github.com/ttacon/chalk"
	"golang.org/x/sys/windows"
)

// Estructura para los offsets combinados
type CombinedOffsets struct {
	// Offsets desde offsets.json
	DwEntityList      uintptr `json:"dwEntityList"`
	DwLocalPlayerPawn uintptr `json:"dwLocalPlayerPawn"`
	DwViewMatrix      uintptr `json:"dwViewMatrix"`

	// Offsets desde client_dll.json
	M_hPlayerPawn          uintptr `json:"m_hPlayerPawn"`
	M_iHealth              uintptr `json:"m_iHealth"`
	M_lifeState            uintptr `json:"m_lifeState"`
	M_iTeamNum             uintptr `json:"m_iTeamNum"`
	M_vOldOrigin           uintptr `json:"m_vOldOrigin"`
	M_pGameSceneNode       uintptr `json:"m_pGameSceneNode"`
	M_modelState           uintptr `json:"m_modelState"`
	M_nodeToWorld          uintptr `json:"m_nodeToWorld"`
	M_sSanitizedPlayerName uintptr `json:"m_sSanitizedPlayerName"`
	M_boneArray            uintptr `json:"m_boneArray"` // Nuevo campo

}

func getValue(data map[string]interface{}, key string) uintptr {
	// Verifica si la clave existe y no es nil
	if value, exists := data[key]; exists && value != nil {
		// Intenta convertir a float64 y luego a uintptr
		if floatValue, ok := value.(float64); ok {
			return uintptr(floatValue)
		}
		log.Fatalf("La clave '%s' no es del tipo esperado (float64)", key)
	}
	log.Fatalf("La clave '%s' no existe o es nil", key)
	return 0
}

func getNestedFieldValue(data map[string]interface{}, dllKey, classKey, fieldKey string) uintptr {
	// Verifica si `client.dll` existe
	dllData, exists := data[dllKey]
	if !exists {
		log.Fatalf("La clave principal '%s' no existe en el JSON", dllKey)
		return 0
	}

	// Verifica si es un mapa
	dllMap, ok := dllData.(map[string]interface{})
	if !ok {
		log.Fatalf("El valor de '%s' no es un mapa", dllKey)
		return 0
	}

	// Verifica si `classes` existe
	classesData, exists := dllMap["classes"]
	if !exists {
		log.Fatalf("La clave 'classes' no existe en '%s'", dllKey)
		return 0
	}

	// Verifica si es un mapa
	classesMap, ok := classesData.(map[string]interface{})
	if !ok {
		log.Fatalf("El valor de 'classes' en '%s' no es un mapa", dllKey)
		return 0
	}

	// Verifica si la clase específica existe
	classData, exists := classesMap[classKey]
	if !exists {
		log.Fatalf("La clase '%s' no existe en 'classes' dentro de '%s'", classKey, dllKey)
		return 0
	}

	// Verifica si es un mapa
	classMap, ok := classData.(map[string]interface{})
	if !ok {
		log.Fatalf("El valor de la clase '%s' no es un mapa", classKey)
		return 0
	}

	// Verifica si `fields` existe
	fieldsData, exists := classMap["fields"]
	if !exists {
		log.Fatalf("La clave 'fields' no existe en la clase '%s'", classKey)
		return 0
	}

	// Verifica si es un mapa
	fieldsMap, ok := fieldsData.(map[string]interface{})
	if !ok {
		log.Fatalf("El valor de 'fields' en la clase '%s' no es un mapa", classKey)
		return 0
	}

	// Verifica si el campo específico existe
	fieldValue, exists := fieldsMap[fieldKey]
	if !exists {
		log.Fatalf("El campo '%s' no existe en 'fields' de la clase '%s'", fieldKey, classKey)
		return 0
	}

	// Convierte a float64 y luego a uintptr
	floatValue, ok := fieldValue.(float64)
	if !ok {
		log.Fatalf("El campo '%s' en 'fields' de la clase '%s' no es del tipo esperado (float64)", fieldKey, classKey)
		return 0
	}
	return uintptr(floatValue)
}

func fetchAndCombineOffsets() {
	const offsetsURL = "https://raw.githubusercontent.com/a2x/cs2-dumper/refs/heads/main/output/offsets.json"
	const clientDllURL = "https://raw.githubusercontent.com/a2x/cs2-dumper/refs/heads/main/output/client_dll.json"
	const animationSystemDllURL = "https://raw.githubusercontent.com/a2x/cs2-dumper/1950b587a5c74bf8968e5f6767deb593b01e6258/output/animationsystem_dll.json"

	// Descarga animationsystem_dll.json
	animationResponse, err := http.Get(animationSystemDllURL)
	if err != nil {
		log.Fatalf("Error al descargar animationsystem_dll.json: %v", err)
	}
	defer animationResponse.Body.Close()
	if animationResponse.StatusCode != http.StatusOK {
		log.Fatalf("Error al descargar animationsystem_dll.json: código de estado %d", animationResponse.StatusCode)
	}
	animationBody, err := ioutil.ReadAll(animationResponse.Body)
	if err != nil {
		log.Fatalf("Error al leer el contenido de animationsystem_dll.json: %v", err)
	}

	// Decodifica el JSON de animationsystem_dll.json
	var animationOffsetsData map[string]interface{}
	err = json.Unmarshal(animationBody, &animationOffsetsData)
	if err != nil {
		log.Fatalf("Error al decodificar animationsystem_dll.json: %v", err)
	}

	// Descarga offsets.json
	offsetsResponse, err := http.Get(offsetsURL)
	if err != nil {
		log.Fatalf("Error al descargar offsets.json: %v", err)
	}
	defer offsetsResponse.Body.Close()
	if offsetsResponse.StatusCode != http.StatusOK {
		log.Fatalf("Error al descargar offsets.json: código de estado %d", offsetsResponse.StatusCode)
	}
	offsetsBody, err := ioutil.ReadAll(offsetsResponse.Body)
	if err != nil {
		log.Fatalf("Error al leer el contenido de offsets.json: %v", err)
	}

	// Descarga client_dll.json
	clientResponse, err := http.Get(clientDllURL)
	if err != nil {
		log.Fatalf("Error al descargar client_dll.json: %v", err)
	}
	defer clientResponse.Body.Close()
	if clientResponse.StatusCode != http.StatusOK {
		log.Fatalf("Error al descargar client_dll.json: código de estado %d", clientResponse.StatusCode)
	}
	clientBody, err := ioutil.ReadAll(clientResponse.Body)
	if err != nil {
		log.Fatalf("Error al leer el contenido de client_dll.json: %v", err)
	}

	// Decodifica ambos JSON en mapas genéricos
	var offsetsData map[string]interface{}
	var clientOffsetsData map[string]interface{}
	err = json.Unmarshal(offsetsBody, &offsetsData)
	if err != nil {
		log.Fatalf("Error al decodificar offsets.json: %v", err)
	}
	err = json.Unmarshal(clientBody, &clientOffsetsData)
	if err != nil {
		log.Fatalf("Error al decodificar client_dll.json: %v", err)
	}
	fmt.Println("Estructura de client_dll.json:")
	for key := range clientOffsetsData {
		fmt.Println("Clave de nivel superior:", key)
	}

	// Asegúrate de que `offsetsData` contenga "client.dll"
	clientDllOffsets, ok := offsetsData["client.dll"].(map[string]interface{})
	if !ok {
		log.Fatalf("Error: 'client.dll' no existe o no es del tipo esperado")
	}

	// se
	// Combina los offsets necesarios
	combinedOffsets := CombinedOffsets{
		// Offsets de offsets.json
		DwEntityList:      getValue(clientDllOffsets, "dwEntityList"),
		DwLocalPlayerPawn: getValue(clientDllOffsets, "dwLocalPlayerPawn"),
		DwViewMatrix:      getValue(clientDllOffsets, "dwViewMatrix"),

		// Offsets de client_dll.json
		M_hPlayerPawn:          getNestedFieldValue(clientOffsetsData, "client.dll", "CCSPlayerController", "m_hPlayerPawn"),
		M_sSanitizedPlayerName: getNestedFieldValue(clientOffsetsData, "client.dll", "CCSPlayerController", "m_sSanitizedPlayerName"),
		M_vOldOrigin:           getNestedFieldValue(clientOffsetsData, "client.dll", "C_BasePlayerPawn", "m_vOldOrigin"),
		M_modelState:           getNestedFieldValue(clientOffsetsData, "client.dll", "CSkeletonInstance", "m_modelState"),
		M_nodeToWorld:          getNestedFieldValue(clientOffsetsData, "client.dll", "CGameSceneNode", "m_nodeToWorld"),
		M_iHealth:              getNestedFieldValue(clientOffsetsData, "client.dll", "C_BaseEntity", "m_iHealth"),
		M_lifeState:            getNestedFieldValue(clientOffsetsData, "client.dll", "C_BaseEntity", "m_lifeState"),
		M_iTeamNum:             getNestedFieldValue(clientOffsetsData, "client.dll", "C_BaseEntity", "m_iTeamNum"),
		M_pGameSceneNode:       getNestedFieldValue(clientOffsetsData, "client.dll", "C_BaseEntity", "m_pGameSceneNode"),

		// Offsets de BoneArray
		M_boneArray: 128,
	}

	// Crea o sobrescribe el archivo combinado offsets.json
	file, err := os.Create("offsets.json")
	if err != nil {
		log.Fatalf("Error al crear el archivo offsets.json: %v", err)
	}
	defer file.Close()

	// Escribe los offsets combinados en formato JSON
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Formato con indentación para mayor legibilidad
	err = encoder.Encode(combinedOffsets)
	if err != nil {
		log.Fatalf("Error al escribir el archivo offsets.json: %v", err)
	}

	fmt.Println("Archivo offsets.json combinado creado exitosamente.")
}

type Matrix [4][4]float32

type Vector3 struct {
	X float32
	Y float32
	Z float32
}

func (v Vector3) Dist(other Vector3) float32 {
	return float32(math.Abs(float64(v.X-other.X)) + math.Abs(float64(v.Y-other.Y)) + math.Abs(float64(v.Z-other.Z)))
}

type Vector2 struct {
	X float32
	Y float32
}

type Rectangle struct {
	Top    float32
	Left   float32
	Right  float32
	Bottom float32
}

type Entity struct {
	Health   int32
	Team     int32
	Name     string
	Position Vector2
	Bones    map[string]Vector2
	HeadPos  Vector3
	Distance float32
	Rect     Rectangle
}

type Offset struct {
	DwViewMatrix           uintptr `json:"dwViewMatrix"`
	DwLocalPlayerPawn      uintptr `json:"dwLocalPlayerPawn"`
	DwEntityList           uintptr `json:"dwEntityList"`
	M_hPlayerPawn          uintptr `json:"m_hPlayerPawn"`
	M_iHealth              uintptr `json:"m_iHealth"`
	M_lifeState            uintptr `json:"m_lifeState"`
	M_iTeamNum             uintptr `json:"m_iTeamNum"`
	M_vOldOrigin           uintptr `json:"m_vOldOrigin"`
	M_pGameSceneNode       uintptr `json:"m_pGameSceneNode"`
	M_modelState           uintptr `json:"m_modelState"`
	M_boneArray            uintptr `json:"m_boneArray"`
	M_nodeToWorld          uintptr `json:"m_nodeToWorld"`
	M_sSanitizedPlayerName uintptr `json:"m_sSanitizedPlayerName"`
}

var (
	user32                     = windows.NewLazySystemDLL("user32.dll")
	gdi32                      = windows.NewLazySystemDLL("gdi32.dll")
	getSystemMetrics           = user32.NewProc("GetSystemMetrics")
	setLayeredWindowAttributes = user32.NewProc("SetLayeredWindowAttributes")
	showCursor                 = user32.NewProc("ShowCursor")
	setTextAlign               = gdi32.NewProc("SetTextAlign")
	createFont                 = gdi32.NewProc("CreateFontW")
	createCompatibleDC         = gdi32.NewProc("CreateCompatibleDC")
	createSolidBrush           = gdi32.NewProc("CreateSolidBrush")
	createPen                  = gdi32.NewProc("CreatePen")
)

var (
	teamCheck           bool   = true
	headCircle          bool   = true
	skeletonRendering   bool   = true
	boxRendering        bool   = true
	nameRendering       bool   = true
	healthBarRendering  bool   = true
	healthTextRendering bool   = true
	frameDelay          uint32 = 15
)

func init() {
	// Ensure main() runs on the main thread.
	runtime.LockOSThread()
}

func logAndSleep(message string, err error) {
	log.Printf("%s: %v\n", message, err)
	time.Sleep(5 * time.Second)
}

func worldToScreen(viewMatrix Matrix, position Vector3) (float32, float32) {
	var screenX float32
	var screenY float32
	screenX = viewMatrix[0][0]*position.X + viewMatrix[0][1]*position.Y + viewMatrix[0][2]*position.Z + viewMatrix[0][3]
	screenY = viewMatrix[1][0]*position.X + viewMatrix[1][1]*position.Y + viewMatrix[1][2]*position.Z + viewMatrix[1][3]
	w := viewMatrix[3][0]*position.X + viewMatrix[3][1]*position.Y + viewMatrix[3][2]*position.Z + viewMatrix[3][3]
	if w < 0.01 {
		return -1, -1
	}
	invw := 1.0 / w
	screenX *= invw
	screenY *= invw
	width, _, _ := getSystemMetrics.Call(0)
	height, _, _ := getSystemMetrics.Call(1)
	widthFloat := float32(width)
	heightFloat := float32(height)
	x := widthFloat / 2
	y := heightFloat / 2
	x += 0.5*screenX*widthFloat + 0.5
	y -= 0.5*screenY*heightFloat + 0.5
	return x, y
}

func getOffsets() Offset {
	var offsets Offset

	// Open the file
	offsetsJson, err := os.Open("offsets.json")
	if err != nil {
		fmt.Println("Error opening offsets.json", err)
		return offsets
	}
	defer offsetsJson.Close()

	// Decode the JSON
	err = json.NewDecoder(offsetsJson).Decode(&offsets)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return offsets
	}
	return offsets
}

func getEntitiesInfo(procHandle windows.Handle, clientDll uintptr, screenWidth uintptr, screenHeight uintptr, offsets Offset) []Entity {
	var entityList uintptr
	var entities []Entity
	err := readSafe(procHandle, clientDll+offsets.DwEntityList, &entityList)
	if err != nil {
		return entities
	}
	var (
		localPlayerP           uintptr
		localPlayerGameScene   uintptr
		localPlayerSceneOrigin Vector3
		localTeam              int32
		listEntry              uintptr
		gameScene              uintptr
		entityController       uintptr
		entityControllerPawn   uintptr
		entityPawn             uintptr
		entityNameAddress      uintptr
		entityBoneArray        uintptr
		entityTeam             int32
		entityHealth           int32
		entityLifeState        int32
		entityName             string
		sanitizedNameStr       string
		entityOrigin           Vector3
		viewMatrix             Matrix
	)
	bones := map[string]int{
		"head":        6,
		"neck_0":      5,
		"spine_1":     4,
		"spine_2":     2,
		"pelvis":      0,
		"arm_upper_L": 8,
		"arm_lower_L": 9,
		"hand_L":      10,
		"arm_upper_R": 13,
		"arm_lower_R": 14,
		"hand_R":      15,
		"leg_upper_L": 22,
		"leg_lower_L": 23,
		"ankle_L":     24,
		"leg_upper_R": 25,
		"leg_lower_R": 26,
		"ankle_R":     27,
	}
	var (
		currentBone      Vector3
		entityHead       Vector3
		entityHeadTop    Vector3
		entityHeadBottom Vector3
	)
	// localPlayerP
	err = readSafe(procHandle, clientDll+offsets.DwLocalPlayerPawn, &localPlayerP)
	if err != nil {
		return entities
	}
	// localPlayerGameScene
	err = readSafe(procHandle, localPlayerP+offsets.M_pGameSceneNode, &localPlayerGameScene)
	if err != nil {
		return entities
	}
	// localPlayerSceneOrigin
	err = readSafe(procHandle, localPlayerGameScene+offsets.M_nodeToWorld, &localPlayerSceneOrigin)
	if err != nil {
		return entities
	}
	// viewMatrix
	err = readSafe(procHandle, clientDll+offsets.DwViewMatrix, &viewMatrix)
	if err != nil {
		return entities
	}
	for i := 0; i < 64; i++ {
		var tempEntity Entity
		var entityBones map[string]Vector2 = make(map[string]Vector2)
		var sanitizedName strings.Builder
		// listEntry
		err = readSafe(procHandle, entityList+uintptr((8*(i&0x7FFF)>>9)+16), &listEntry)
		if err != nil {
			return entities
		}
		if listEntry == 0 {
			continue
		}
		// entityController
		err = readSafe(procHandle, listEntry+uintptr(120)*uintptr(i&0x1FF), &entityController)
		if err != nil {
			return entities
		}
		if entityController == 0 {
			continue
		}
		// entityControllerPawn
		err = readSafe(procHandle, entityController+offsets.M_hPlayerPawn, &entityControllerPawn)
		if err != nil {
			return entities
		}
		if entityControllerPawn == 0 {
			continue
		}
		// listEntry
		err = readSafe(procHandle, entityList+uintptr(0x8*((entityControllerPawn&0x7FFF)>>9)+16), &listEntry)
		if err != nil {
			return entities
		}
		if listEntry == 0 {
			continue
		}
		// entityPawn
		err = readSafe(procHandle, listEntry+uintptr(120)*uintptr(entityControllerPawn&0x1FF), &entityPawn)
		if err != nil {
			return entities
		}
		if entityPawn == 0 {
			continue
		}
		if entityPawn == localPlayerP {
			continue
		}
		// entityLifeState
		err = readSafe(procHandle, entityPawn+offsets.M_lifeState, &entityLifeState)
		if err != nil {
			return entities
		}
		if entityLifeState != 256 {
			continue
		}
		// entityTeam
		err = readSafe(procHandle, entityPawn+offsets.M_iTeamNum, &entityTeam)
		if err != nil {
			return entities
		}
		if entityTeam == 0 {
			continue
		}
		if teamCheck {
			// localTeam
			err = readSafe(procHandle, localPlayerP+offsets.M_iTeamNum, &localTeam)
			if err != nil {
				return entities
			}
			if localTeam == entityTeam {
				continue
			}
		}
		// entityHealth
		err = readSafe(procHandle, entityPawn+offsets.M_iHealth, &entityHealth)
		if err != nil {
			return entities
		}
		if entityHealth < 1 || entityHealth > 100 {
			continue
		}
		// entityNameAddress
		err = readSafe(procHandle, entityController+offsets.M_sSanitizedPlayerName, &entityNameAddress)
		if err != nil {
			return entities
		}
		// entityName
		err = readSafe(procHandle, entityNameAddress, &entityName)
		if err != nil {
			return entities
		}
		if entityName == "" {
			continue
		}
		for _, c := range entityName {
			if unicode.IsLetter(c) || unicode.IsDigit(c) || unicode.IsPunct(c) || unicode.IsSpace(c) {
				sanitizedName.WriteRune(c)
			}
		}
		sanitizedNameStr = sanitizedName.String()
		// gameScene
		err = readSafe(procHandle, entityPawn+offsets.M_pGameSceneNode, &gameScene)
		if err != nil {
			return entities
		}
		if gameScene == 0 {
			continue
		}
		// entityBoneArray
		err = readSafe(procHandle, gameScene+offsets.M_modelState+offsets.M_boneArray, &entityBoneArray)
		if err != nil {
			return entities
		}
		if entityBoneArray == 0 {
			continue
		}
		// entityOrigin
		err = readSafe(procHandle, entityPawn+offsets.M_vOldOrigin, &entityOrigin)
		if err != nil {
			return entities
		}
		// boneArray
		for boneName, boneIndex := range bones {
			err = readSafe(procHandle, entityBoneArray+uintptr(boneIndex)*32, &currentBone)
			if err != nil {
				return entities
			}
			if boneName == "head" {
				entityHead = currentBone
				if !skeletonRendering {
					break
				}
			}
			boneX, boneY := worldToScreen(viewMatrix, currentBone)
			entityBones[boneName] = Vector2{boneX, boneY}
		}
		entityHeadTop = Vector3{entityHead.X, entityHead.Y, entityHead.Z + 7}
		entityHeadBottom = Vector3{entityHead.X, entityHead.Y, entityHead.Z - 5}
		screenPosHeadX, screenPosHeadTopY := worldToScreen(viewMatrix, entityHeadTop)
		_, screenPosHeadBottomY := worldToScreen(viewMatrix, entityHeadBottom)
		screenPosFeetX, screenPosFeetY := worldToScreen(viewMatrix, entityOrigin)
		entityBoxTop := Vector3{entityOrigin.X, entityOrigin.Y, entityOrigin.Z + 70}
		_, screenPosBoxTop := worldToScreen(viewMatrix, entityBoxTop)
		if screenPosHeadX <= -1 || screenPosFeetY <= -1 || screenPosHeadX >= float32(screenWidth) || screenPosHeadTopY >= float32(screenHeight) {
			continue
		}
		boxHeight := screenPosFeetY - screenPosBoxTop

		tempEntity.Health = entityHealth
		tempEntity.Team = entityTeam
		tempEntity.Name = sanitizedNameStr
		tempEntity.Distance = entityOrigin.Dist(localPlayerSceneOrigin)
		tempEntity.Position = Vector2{screenPosFeetX, screenPosFeetY}
		tempEntity.Bones = entityBones
		tempEntity.HeadPos = Vector3{screenPosHeadX, screenPosHeadTopY, screenPosHeadBottomY}
		tempEntity.Rect = Rectangle{screenPosBoxTop, screenPosFeetX - boxHeight/4, screenPosFeetX + boxHeight/4, screenPosFeetY}

		entities = append(entities, tempEntity)
	}
	return entities
}

func drawSkeleton(hdc win.HDC, pen uintptr, bones map[string]Vector2) {
	win.SelectObject(hdc, win.HGDIOBJ(pen))
	win.MoveToEx(hdc, int(bones["head"].X), int(bones["head"].Y), nil)
	win.LineTo(hdc, int32(bones["neck_0"].X), int32(bones["neck_0"].Y))
	win.LineTo(hdc, int32(bones["spine_1"].X), int32(bones["spine_1"].Y))
	win.LineTo(hdc, int32(bones["spine_2"].X), int32(bones["spine_2"].Y))
	win.LineTo(hdc, int32(bones["pelvis"].X), int32(bones["pelvis"].Y))
	win.LineTo(hdc, int32(bones["leg_upper_L"].X), int32(bones["leg_upper_L"].Y))
	win.LineTo(hdc, int32(bones["leg_lower_L"].X), int32(bones["leg_lower_L"].Y))
	win.LineTo(hdc, int32(bones["ankle_L"].X), int32(bones["ankle_L"].Y))
	win.MoveToEx(hdc, int(bones["pelvis"].X), int(bones["pelvis"].Y), nil)
	win.LineTo(hdc, int32(bones["leg_upper_R"].X), int32(bones["leg_upper_R"].Y))
	win.LineTo(hdc, int32(bones["leg_lower_R"].X), int32(bones["leg_lower_R"].Y))
	win.LineTo(hdc, int32(bones["ankle_R"].X), int32(bones["ankle_R"].Y))
	win.MoveToEx(hdc, int(bones["spine_1"].X), int(bones["spine_1"].Y), nil)
	win.LineTo(hdc, int32(bones["arm_upper_L"].X), int32(bones["arm_upper_L"].Y))
	win.LineTo(hdc, int32(bones["arm_lower_L"].X), int32(bones["arm_lower_L"].Y))
	win.LineTo(hdc, int32(bones["hand_L"].X), int32(bones["hand_L"].Y))
	win.MoveToEx(hdc, int(bones["spine_1"].X), int(bones["spine_1"].Y), nil)
	win.LineTo(hdc, int32(bones["arm_upper_R"].X), int32(bones["arm_upper_R"].Y))
	win.LineTo(hdc, int32(bones["arm_lower_R"].X), int32(bones["arm_lower_R"].Y))
	win.LineTo(hdc, int32(bones["hand_R"].X), int32(bones["hand_R"].Y))
}

func renderEntityInfo(hdc win.HDC, tPen uintptr, gPen uintptr, oPen uintptr, hPen uintptr, rect Rectangle, hp int32, name string, headPos Vector3) {
	if boxRendering {
		// Box
		win.SelectObject(hdc, win.HGDIOBJ(tPen))
		win.MoveToEx(hdc, int(rect.Left), int(rect.Top), nil)
		win.LineTo(hdc, int32(rect.Right), int32(rect.Top))
		win.LineTo(hdc, int32(rect.Right), int32(rect.Bottom))
		win.LineTo(hdc, int32(rect.Left), int32(rect.Bottom))
		win.LineTo(hdc, int32(rect.Left), int32(rect.Top))

		// Box outline
		win.SelectObject(hdc, win.HGDIOBJ(oPen))
		win.MoveToEx(hdc, int(rect.Left)-1, int(rect.Top)-1, nil)
		win.LineTo(hdc, int32(rect.Right)-1, int32(rect.Top)+1)
		win.LineTo(hdc, int32(rect.Right)+1, int32(rect.Bottom)+1)
		win.LineTo(hdc, int32(rect.Left)+1, int32(rect.Bottom)-1)
		win.LineTo(hdc, int32(rect.Left)-1, int32(rect.Top)-1)
		win.MoveToEx(hdc, int(rect.Left)+1, int(rect.Top)+1, nil)
		win.LineTo(hdc, int32(rect.Right)+1, int32(rect.Top)-1)
		win.LineTo(hdc, int32(rect.Right)-1, int32(rect.Bottom)-1)
		win.LineTo(hdc, int32(rect.Left)-1, int32(rect.Bottom)+1)
		win.LineTo(hdc, int32(rect.Left)+1, int32(rect.Top)+1)
	}

	if headCircle {
		// Head with outline
		radius := int32((int32(headPos.Z) - int32(headPos.Y)) / 2)
		win.SelectObject(hdc, win.HGDIOBJ(oPen))
		win.Ellipse(hdc, int32(headPos.X)-radius-1, int32(headPos.Y)-1, int32(headPos.X)+radius+1, int32(headPos.Z)+1)
		win.SelectObject(hdc, win.HGDIOBJ(hPen))
		win.Ellipse(hdc, int32(headPos.X)-radius, int32(headPos.Y), int32(headPos.X)+radius, int32(headPos.Z))
		win.SelectObject(hdc, win.HGDIOBJ(oPen))
		win.Ellipse(hdc, int32(headPos.X)-radius+1, int32(headPos.Y)+1, int32(headPos.X)+radius-1, int32(headPos.Z)-1)
	}

	if healthBarRendering {
		// Health bar
		win.SelectObject(hdc, win.HGDIOBJ(gPen))
		win.MoveToEx(hdc, int(rect.Left)-4, int(rect.Bottom)+1-int(float64(int(rect.Bottom)+1-int(rect.Top))*float64(hp)/100.0), nil)
		win.LineTo(hdc, int32(rect.Left)-4, int32(rect.Bottom)+1)

		// Health bar outline
		win.SelectObject(hdc, win.HGDIOBJ(oPen))
		win.MoveToEx(hdc, int(rect.Left)-5, int(rect.Top)-1, nil)
		win.LineTo(hdc, int32(rect.Left)-5, int32(rect.Bottom)+1)
		win.LineTo(hdc, int32(rect.Left)-3, int32(rect.Bottom)+1)
		win.LineTo(hdc, int32(rect.Left)-3, int32(rect.Top)-1)
		win.LineTo(hdc, int32(rect.Left)-5, int32(rect.Top)-1)
	}

	if healthTextRendering {
		// Health text
		text, _ := windows.UTF16PtrFromString(fmt.Sprintf("%d", hp))
		win.SetTextColor(hdc, win.RGB(byte(0), byte(255), byte(50)))
		// Set text right alignment
		setTextAlign.Call(uintptr(hdc), 0x00000002)
		if healthBarRendering {
			win.TextOut(hdc, int32(rect.Left)-8, int32(int(rect.Bottom)+1-int(float64(int(rect.Bottom)+1-int(rect.Top))*float64(hp)/100.0)), text, int32(len(fmt.Sprintf("%d", hp))))
		} else {
			win.TextOut(hdc, int32(rect.Left)-4, int32(rect.Top), text, int32(len(fmt.Sprintf("%d", hp))))
		}
	}

	if nameRendering {
		// Name
		text, _ := windows.UTF16PtrFromString(name)
		win.SetTextColor(hdc, win.RGB(byte(255), byte(255), byte(255)))
		setTextAlign.Call(uintptr(hdc), 0x00000006) // Set text alignment to center
		win.TextOut(hdc, int32(rect.Left)+int32((int32(rect.Right)-int32(rect.Left))/2), int32(rect.Top)-14, text, int32(len(name)))
	}
}

func windowProc(hwnd win.HWND, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case win.WM_TIMER:
		return 0
	case win.WM_DESTROY:
		win.PostQuitMessage(0)
		return 0
	default:
		return win.DefWindowProc(hwnd, msg, wParam, lParam)
	}
}

func initWindow(screenWidth uintptr, screenHeight uintptr) win.HWND {

	className, err := windows.UTF16PtrFromString("cs2goWindow")
	if err != nil {
		logAndSleep("Error creating window class name", err)
		return 0
	}
	windowTitle, err := windows.UTF16PtrFromString("cs2go")
	if err != nil {
		logAndSleep("Error creating window title", err)
		return 0
	}

	// Register window class
	wc := win.WNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(win.WNDCLASSEX{})),
		Style:         win.CS_HREDRAW | win.CS_VREDRAW,
		LpfnWndProc:   syscall.NewCallback(windowProc),
		CbWndExtra:    0,
		HInstance:     win.GetModuleHandle(nil),
		HIcon:         win.LoadIcon(0, (*uint16)(unsafe.Pointer(uintptr(win.IDI_APPLICATION)))),
		HCursor:       win.LoadCursor(0, (*uint16)(unsafe.Pointer(uintptr(win.IDC_ARROW)))),
		HbrBackground: win.COLOR_WINDOW,
		LpszMenuName:  nil,
		LpszClassName: className,
		HIconSm:       win.LoadIcon(0, (*uint16)(unsafe.Pointer(uintptr(win.IDI_APPLICATION)))),
	}

	if atom := win.RegisterClassEx(&wc); atom == 0 {
		logAndSleep("Error registering window class", fmt.Errorf("%v", win.GetLastError()))
		return 0
	}

	// Create window
	hInstance := win.GetModuleHandle(nil)
	hwnd := win.CreateWindowEx(
		win.WS_EX_TOPMOST|win.WS_EX_NOACTIVATE|win.WS_EX_LAYERED,
		className,
		windowTitle,
		win.WS_POPUP,
		0,
		0,
		int32(screenWidth),
		int32(screenHeight),
		0,
		0,
		hInstance,
		nil,
	)
	if hwnd == 0 {
		logAndSleep("Error creating window", fmt.Errorf("%v", win.GetLastError()))
		return 0
	}

	result, _, _ := setLayeredWindowAttributes.Call(uintptr(hwnd), 0x000000, 0, 0x00000001)
	if result == 0 {
		logAndSleep("Error setting layered window attributes", fmt.Errorf("%v", win.GetLastError()))
	}
	// Get the current extended window style
	style := win.GetWindowLongPtr(hwnd, win.GWL_EXSTYLE)

	// Add the WS_EX_TRANSPARENT style
	style |= win.WS_EX_TRANSPARENT

	// Set the new extended window style
	win.SetWindowLongPtr(hwnd, win.GWL_EXSTYLE, style)

	showCursor.Call(0)

	// Show window
	win.ShowWindow(hwnd, win.SW_SHOWDEFAULT)
	return hwnd
}

func cliMenu() {
	for {
		fmt.Println(chalk.Green.Color("-------------------------------------------------------------------------"))
		fmt.Println(chalk.Bold.TextStyle("\t\t" +
			"░█████╗░░██████╗██████╗░░██████╗░░█████╗░██╗    ██████╗░███████╗████████╗░█████╗░██╗░░░░░██████╗░\n" +
			"██╔══██╗██╔════╝╚════██╗██╔════╝░██╔══██╗╚═╝    ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██║░░░░░██╔══██╗\n" +
			"██║░░╚═╝╚█████╗░░░███╔═╝██║░░██╗░██║░░██║░░░    ██████╔╝█████╗░░░░░██║░░░██║░░██║██║░░░░░██║░░██║\n" +
			"██║░░██╗░╚═══██╗██╔══╝░░██║░░╚██╗██║░░██║░░░    ██╔══██╗██╔══╝░░░░░██║░░░██║░░██║██║░░░░░██║░░██║\n" +
			"╚█████╔╝██████╔╝███████╗╚██████╔╝╚█████╔╝██╗    ██║░░██║███████╗░░░██║░░░╚█████╔╝███████╗██████╔╝\n" +
			"░╚════╝░╚═════╝░╚══════╝░╚═════╝░░╚════╝░╚═╝    ╚═╝░░╚═╝╚══════╝░░░╚═╝░░░░╚════╝░╚══════╝╚═════╝░"))
		fmt.Println(chalk.Green.Color("-------------------------------------------------------------------------"))

		if teamCheck {
			fmt.Println(chalk.Green.Color("[1] Teammate Highlighting [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[1] Teammate Highlighting [OFF]"))
		}
		if headCircle {
			fmt.Println(chalk.Green.Color("[2] Head Circles [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[2] Head Circles [OFF]"))
		}
		if skeletonRendering {
			fmt.Println(chalk.Green.Color("[3] Skeleton Rendering [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[3] Skeleton Rendering [OFF]"))
		}
		if boxRendering {
			fmt.Println(chalk.Green.Color("[4] ESP Boxes [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[4] ESP Boxes [OFF]"))
		}
		if healthBarRendering {
			fmt.Println(chalk.Green.Color("[5] HP Bar [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[5] HP Bar [OFF]"))
		}
		if healthTextRendering {
			fmt.Println(chalk.Green.Color("[6] HP Text [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[6] HP Text [OFF]"))
		}
		if nameRendering {
			fmt.Println(chalk.Green.Color("[7] Noob Names [ON]"))
		} else {
			fmt.Println(chalk.Red.Color("[7] Noob Names [OFF]"))
		}
		fmt.Println(chalk.Cyan.Color("[8] Adjust Frame Delay [") + fmt.Sprint(frameDelay) + chalk.Cyan.Color("]"))
		fmt.Println(chalk.Red.Color("\n[9] Exit\n"))
		fmt.Print(chalk.Cyan.Color("[Enter number]: "))
		var input string
		fmt.Scanln(&input)
		switch input {
		case "1":
			teamCheck = !teamCheck
		case "2":
			headCircle = !headCircle
		case "3":
			skeletonRendering = !skeletonRendering
		case "4":
			boxRendering = !boxRendering
		case "5":
			healthBarRendering = !healthBarRendering
		case "6":
			healthTextRendering = !healthTextRendering
		case "7":
			nameRendering = !nameRendering
		case "8":
			fmt.Println(chalk.Red.Color("Higher frame delay = lower performance impact but higher ESP latency"))
			fmt.Print(chalk.Cyan.Color("[Enter frame delay]: "))
			var delay uint32
			fmt.Scanln(&delay)
			frameDelay = delay
		case "9":
			os.Exit(0)
		default:
			fmt.Println(chalk.Red.Color("Invalid selection"))
			time.Sleep(1 * time.Second)
		}
		// Clear the console
		fmt.Print("\033[H\033[2J")
	}
}

func main() {

	fetchAndCombineOffsets()

	go cliMenu()

	screenWidth, _, _ := getSystemMetrics.Call(0)
	screenHeight, _, _ := getSystemMetrics.Call(1)

	hwnd := initWindow(screenWidth, screenHeight)
	if hwnd == 0 {
		logAndSleep("Error creating window", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DestroyWindow(hwnd)

	// win.SetCursor()

	pid, err := findProcessId("cs2.exe")
	if err != nil {
		logAndSleep("Error finding process ID", err)
		return
	}

	clientDll, err := getModuleBaseAddress(pid, "client.dll")
	if err != nil {
		logAndSleep("Error getting client.dll base address", err)
		return
	}

	procHandle, err := getProcessHandle(pid)
	if err != nil {
		logAndSleep("Error getting process handle", err)
		return
	}

	hdc := win.GetDC(hwnd)
	if hdc == 0 {
		logAndSleep("Error getting device context", fmt.Errorf("%v", win.GetLastError()))
		return
	}

	bgBrush, _, _ := createSolidBrush.Call(uintptr(0x000000))
	if bgBrush == 0 {
		logAndSleep("Error creating brush", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(bgBrush))
	redPen, _, _ := createPen.Call(win.PS_SOLID, 1, 0x7a78ff)
	if redPen == 0 {
		logAndSleep("Error creating pen", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(redPen))
	greenPen, _, _ := createPen.Call(win.PS_SOLID, 1, 0x7dff78)
	if greenPen == 0 {
		logAndSleep("Error creating pen", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(greenPen))
	bluePen, _, _ := createPen.Call(win.PS_SOLID, 1, 0xff8e78)
	if bluePen == 0 {
		logAndSleep("Error creating pen", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(bluePen))
	bonePen, _, _ := createPen.Call(win.PS_SOLID, 1, 0xffffff)
	if bonePen == 0 {
		logAndSleep("Error creating pen", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(bonePen))
	outlinePen, _, _ := createPen.Call(win.PS_SOLID, 1, 0x000001)
	if outlinePen == 0 {
		logAndSleep("Error creating pen", fmt.Errorf("%v", win.GetLastError()))
		return
	}
	defer win.DeleteObject(win.HGDIOBJ(outlinePen))

	font, _, _ := createFont.Call(12, 0, 0, 0, win.FW_HEAVY, 0, 0, 0, win.DEFAULT_CHARSET, win.OUT_DEFAULT_PRECIS, win.CLIP_DEFAULT_PRECIS, win.DEFAULT_QUALITY, win.DEFAULT_PITCH|win.FF_DONTCARE, 0)

	offsets := getOffsets()

	var msg win.MSG

	for win.GetMessage(&msg, 0, 0, 0) > 0 {
		win.TranslateMessage(&msg)
		win.DispatchMessage(&msg)

		win.SetTimer(hwnd, 1, frameDelay, 0)

		memhdc, _, _ := createCompatibleDC.Call(uintptr(hdc))
		memBitmap := win.CreateCompatibleBitmap(hdc, int32(screenWidth), int32(screenHeight))
		win.SelectObject(win.HDC(memhdc), win.HGDIOBJ(memBitmap))
		win.SelectObject(win.HDC(memhdc), win.HGDIOBJ(bgBrush))
		win.SetBkMode(win.HDC(memhdc), win.TRANSPARENT)
		win.SelectObject(win.HDC(memhdc), win.HGDIOBJ(font))

		entities := getEntitiesInfo(procHandle, clientDll, screenWidth, screenHeight, offsets)
		for _, entity := range entities {
			if entity.Distance < 35 {
				continue
			}
			if skeletonRendering {
				drawSkeleton(win.HDC(memhdc), bonePen, entity.Bones)
			}
			if entity.Team == 2 {
				renderEntityInfo(win.HDC(memhdc), redPen, greenPen, outlinePen, bonePen, entity.Rect, entity.Health, entity.Name, entity.HeadPos)
			} else {
				renderEntityInfo(win.HDC(memhdc), bluePen, greenPen, outlinePen, bonePen, entity.Rect, entity.Health, entity.Name, entity.HeadPos)
			}
		}
		win.BitBlt(hdc, 0, 0, int32(screenWidth), int32(screenHeight), win.HDC(memhdc), 0, 0, win.SRCCOPY)

		// Delete the memory bitmap and device context
		win.DeleteObject(win.HGDIOBJ(memBitmap))
		win.DeleteDC(win.HDC(memhdc))
	}
}
